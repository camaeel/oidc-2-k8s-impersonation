package server

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
	dummy_oidc_server "github.com/camaeel/oidc-2-k8s-impersonation/internal/dummy_oidc_server"
	"github.com/camaeel/oidc-2-k8s-impersonation/internal/proxy"
)

// hijackableRecorder is an httptest.ResponseRecorder that also implements
// http.Hijacker and http.Flusher, to simulate a real net/http ResponseWriter
// as used when serving actual connections (WebSocket/SPDY upgrades, chunked
// streaming responses).
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
	flushed  bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	server, _ := net.Pipe()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func (h *hijackableRecorder) Flush() {
	h.flushed = true
	h.ResponseRecorder.Flush()
}

// TestResponseRecorder_ForwardsHijacker ensures the withAccessLog wrapper
// still allows the reverse proxy to hijack the connection for Upgrade
// (WebSocket/SPDY) requests, e.g. `kubectl exec`/`attach`/`port-forward`.
func TestResponseRecorder_ForwardsHijacker(t *testing.T) {
	underlying := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}

	handler := withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		require.True(t, ok, "wrapped ResponseWriter must implement http.Hijacker")
		conn, _, err := hj.Hijack()
		require.NoError(t, err)
		defer conn.Close()
	}))

	req := httptest.NewRequest(http.MethodGet, "/watch?watch=true", nil)
	handler.ServeHTTP(underlying, req)

	assert.True(t, underlying.hijacked, "Hijack() should have been forwarded to the underlying ResponseWriter")
}

// TestResponseRecorder_ForwardsFlusher ensures streaming responses (e.g.
// `watch` requests) can still be flushed promptly through the wrapper.
func TestResponseRecorder_ForwardsFlusher(t *testing.T) {
	underlying := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}

	handler := withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		require.True(t, ok, "wrapped ResponseWriter must implement http.Flusher")
		w.WriteHeader(http.StatusOK)
		f.Flush()
	}))

	req := httptest.NewRequest(http.MethodGet, "/watch?watch=true", nil)
	handler.ServeHTTP(underlying, req)

	assert.True(t, underlying.flushed, "Flush() should have been forwarded to the underlying ResponseWriter")
}

// TestResponseRecorder_CapturesStatus ensures the status-capturing behavior
// used for access logging still works after adding Hijacker/Flusher passthrough.
func TestResponseRecorder_CapturesStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	rr := &responseRecorder{ResponseWriter: rec, status: http.StatusOK}

	rr.WriteHeader(http.StatusTeapot)

	assert.Equal(t, http.StatusTeapot, rr.status)
	assert.Equal(t, http.StatusTeapot, rec.Code)
}

// TestWithAccessLog_ProxiesProtocolUpgrade_Integration is an end-to-end
// regression test for the production bug reported against real WebSocket/SPDY
// upgrade traffic (e.g. `kubectl exec`/`attach`/`port-forward`, or a client
// watching over a WebSocket connection): the reverse proxy previously failed
// with "can't switch protocols using non-Hijacker ResponseWriter" because
// withAccessLog's responseRecorder didn't forward http.Hijacker.
//
// This test wires together the full real stack — a real TCP listener via
// httptest.NewServer (so the ResponseWriter is the genuine net/http one that
// implements http.Hijacker), AuthMiddleware/OIDC verification, and
// httputil.ReverseProxy — and confirms an Upgrade request tunnels bytes in
// both directions end to end.
func TestWithAccessLog_ProxiesProtocolUpgrade_Integration(t *testing.T) {
	oidcSrv, err := dummy_oidc_server.SetupDummyOIDCServer(t)
	require.NoError(t, err)

	// Backend that performs a raw protocol upgrade handshake and then echoes
	// back anything it receives, prefixed with "echo:". This stands in for a
	// kube-apiserver exec/attach/port-forward (or WebSocket watch) endpoint.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "test-protocol" {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		require.True(t, ok)
		conn, _, err := hj.Hijack()
		require.NoError(t, err)
		defer conn.Close()

		_, err = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-protocol\r\n\r\n"))
		require.NoError(t, err)

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("echo:"))
		_, _ = conn.Write(buf[:n])
	}))
	defer backend.Close()

	cfg := config.Config{
		Upstream:    backend.URL,
		Issuer:      oidcSrv.Issuer,
		GroupsClaim: "groups",
		UserClaim:   "sub",
	}
	handler, err := proxy.NewReverseProxy(cfg)
	require.NoError(t, err)

	frontend := httptest.NewServer(withAccessLog(handler))
	defer frontend.Close()

	token, err := oidcSrv.GenerateJWT(map[string]interface{}{"sub": "alice"})
	require.NoError(t, err)

	conn, err := net.Dial("tcp", frontend.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	req := "GET / HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Authorization: Bearer " + token + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: test-protocol\r\n\r\n"
	_, err = conn.Write([]byte(req))
	require.NoError(t, err)

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, statusLine, "101", "expected successful protocol switch, got: %s", statusLine)

	// Consume the rest of the response headers up to the blank line.
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" {
			break
		}
	}

	// Send a message through the tunnel and verify the backend's echo comes
	// back through the proxy, proving the hijacked connection is fully
	// bidirectional end to end.
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	resp := make([]byte, 32)
	n, err := reader.Read(resp)
	require.NoError(t, err)
	assert.Equal(t, "echo:ping", string(resp[:n]))
}
