package observability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// statusResponse is the JSON body returned by health endpoints.
type statusResponse struct {
	Status string `json:"status"`
}

// NewHandler returns an http.Handler that serves /livez and /readyz endpoints.
func NewHandler(probe *ReadinessProbe) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if probe.IsReady() {
			writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "not_ready"})
		}
	})

	return mux
}

// Start starts the observability HTTP server on the given port.
// It blocks until the context is cancelled, then gracefully shuts down.
func Start(ctx context.Context, port int, probe *ReadinessProbe) error {
	handler := NewHandler(probe)
	addr := fmt.Sprintf(":%d", port)

	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting observability server", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down observability server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// ListenAndStart is like Start but uses an existing listener.
// This is useful for testing where you want to control the port.
func ListenAndStart(ctx context.Context, listener net.Listener, probe *ReadinessProbe) error {
	handler := NewHandler(probe)
	srv := &http.Server{Handler: handler}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
