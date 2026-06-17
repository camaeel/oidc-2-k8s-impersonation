package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
)

func TestNewReverseProxy_forwardsRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello-backend"))
	}))
	defer backend.Close()

	h, err := NewReverseProxy(config.Config{Upstream: backend.URL})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	proxySrv := httptest.NewServer(h)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/testpath?x=1")
	if err != nil {
		t.Fatalf("failed to GET from proxy: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "hello-backend" {
		t.Fatalf("unexpected response body: %q", string(b))
	}
}
