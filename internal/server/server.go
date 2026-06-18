package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"log/slog"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
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

// Start starts an HTTP server that proxies all requests to the configured upstream.
// This call blocks until the server shuts down (terminated by signal) or an error occurs.
func Start(cfg config.Config) error {
	if cfg.Upstream == "" {
		return fmt.Errorf("upstream not configured")
	}

	handler, err := proxy.NewReverseProxy(cfg)
	if err != nil {
		return fmt.Errorf("failed to create reverse proxy: %w", err)
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: withAccessLog(handler),
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting HTTP proxy server", "addr", addr, "upstream", cfg.Upstream)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	// Wait for termination signal or server error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("shutting down server", "signal", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			return fmt.Errorf("server shutdown failed: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}
