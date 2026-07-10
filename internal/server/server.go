package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"log/slog"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
	"github.com/camaeel/oidc-2-k8s-impersonation/internal/observability"
	"github.com/camaeel/oidc-2-k8s-impersonation/internal/proxy"
)

// responseRecorder wraps http.ResponseWriter to capture the status code.
type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Hijack implements http.Hijacker by delegating to the underlying ResponseWriter.
// Required for httputil.ReverseProxy to tunnel Upgrade (WebSocket/SPDY) requests.
func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}

// Flush implements http.Flusher by delegating to the underlying ResponseWriter.
// Required so streaming/chunked responses (e.g. `watch` requests) are flushed
// to the client promptly instead of being buffered.
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withAccessLog wraps h and emits one INFO log line per request regardless of
// the configured LOG_LEVEL (i.e. it is always visible).
func withAccessLog(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		slog.Info("handled request",
			"method", r.Method,
			"path", r.URL.RequestURI(),
			"status", rec.status,
			"duration", time.Since(start).Round(time.Millisecond),
			"remote", r.RemoteAddr,
		)
	})
}

// Start starts the proxy and observability servers.
// The observability server (/livez, /readyz) starts immediately.
// The proxy server starts after OIDC provider discovery completes.
// The readiness probe is marked ready only after the proxy server is listening.
// This call blocks until a termination signal is received or a fatal error occurs.
func Start(cfg config.Config) error {
	if cfg.Upstream == "" {
		return fmt.Errorf("upstream not configured")
	}

	// 1. Create readiness probe (not ready yet).
	probe := observability.NewReadinessProbe()

	// 2. Start observability server immediately so /livez is available during OIDC discovery.
	obsCtx, obsCancel := context.WithCancel(context.Background())
	defer obsCancel()
	obsErrCh := make(chan error, 1)
	go func() {
		obsErrCh <- observability.Start(obsCtx, cfg.ObservabilityPort, probe)
	}()

	// 3. Build the reverse proxy handler (blocks during OIDC provider discovery with retries).
	handler, err := proxy.NewReverseProxy(cfg)
	if err != nil {
		return fmt.Errorf("failed to create reverse proxy: %w", err)
	}

	// 4. Bind the proxy listener before marking ready — ensures the port is open.
	proxyAddr := fmt.Sprintf(":%d", cfg.Port)
	proxyListener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", proxyAddr, err)
	}

	srv := &http.Server{
		Handler: withAccessLog(handler),
	}

	proxyErrCh := make(chan error, 1)
	go func() {
		slog.Info("starting HTTP proxy server", "addr", proxyAddr, "upstream", cfg.Upstream)
		if err := srv.Serve(proxyListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			proxyErrCh <- err
			return
		}
		proxyErrCh <- nil
	}()

	// 5. Mark ready — proxy listener is bound (kernel queues incoming connections),
	//    OIDC is configured, Serve() goroutine is launched. Accepting the small race
	//    that Serve's accept loop may start a moment after MarkReady.
	probe.MarkReady()
	slog.Info("proxy is ready", "addr", proxyAddr)

	// Wait for termination signal or server error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("shutting down", "signal", sig)

		// Mark not ready first — k8s stops sending traffic.
		probe.MarkNotReady()

		// Gracefully shut down the proxy server.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("proxy server shutdown error", "error", err)
		}
		<-proxyErrCh

		// Stop observability server.
		obsCancel()
		<-obsErrCh

		return nil

	case err := <-proxyErrCh:
		obsCancel()
		return fmt.Errorf("proxy server error: %w", err)

	case err := <-obsErrCh:
		return fmt.Errorf("observability server error: %w", err)
	}
}
