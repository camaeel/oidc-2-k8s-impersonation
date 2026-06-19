package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantToken  string
		wantErr    bool
	}{
		{
			name:       "empty header",
			authHeader: "",
			wantToken:  "",
			wantErr:    false,
		},
		{
			name:       "valid bearer lowercase",
			authHeader: "bearer my-token-123",
			wantToken:  "my-token-123",
			wantErr:    false,
		},
		{
			name:       "valid Bearer mixed case",
			authHeader: "Bearer my-token-123",
			wantToken:  "my-token-123",
			wantErr:    false,
		},
		{
			name:       "valid BEARER uppercase",
			authHeader: "BEARER my-token-123",
			wantToken:  "my-token-123",
			wantErr:    false,
		},
		{
			name:       "bearer with extra spaces",
			authHeader: "  Bearer   my-token-123  ",
			wantToken:  "my-token-123",
			wantErr:    false,
		},
		{
			name:       "not bearer scheme",
			authHeader: "Basic dXNlcjpwYXNz",
			wantErr:    true,
		},
		{
			name:       "bearer with empty token",
			authHeader: "Bearer ",
			wantErr:    true,
		},
		{
			name:       "just bearer word",
			authHeader: "Bearer",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractBearerToken(tt.authHeader)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantToken {
				t.Errorf("extractBearerToken() = %q, want %q", got, tt.wantToken)
			}
		})
	}
}

// mockVerifier implements TokenVerifier for testing.
type mockVerifier struct {
	token *oidc.IDToken
	err   error
}

func (m *mockVerifier) Verify(_ context.Context, _ string) (*oidc.IDToken, error) {
	return m.token, m.err
}

func TestAuthMiddleware_noAuth_noVerifier(t *testing.T) {
	cfg := config.Config{Upstream: "http://localhost"}

	var receivedHeaders http.Header
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	}), nil, cfg)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Impersonate-User", "evil")
	req.Header.Set("Impersonate-Group", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if receivedHeaders.Get("Impersonate-User") != "" {
		t.Error("Impersonate-User header should be stripped")
	}
	if receivedHeaders.Get("Impersonate-Group") != "" {
		t.Error("Impersonate-Group header should be stripped")
	}
}

func TestAuthMiddleware_noAuth_withVerifier(t *testing.T) {
	verifier := &mockVerifier{}
	cfg := config.Config{Upstream: "http://localhost"}
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach backend")
	}), verifier, cfg)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_invalidBearerScheme(t *testing.T) {
	verifier := &mockVerifier{}
	cfg := config.Config{Upstream: "http://localhost"}
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach backend")
	}), verifier, cfg)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_verifyFails(t *testing.T) {
	verifier := &mockVerifier{err: context.DeadlineExceeded}
	cfg := config.Config{Upstream: "http://localhost"}
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach backend")
	}), verifier, cfg)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_authWithNoVerifier(t *testing.T) {
	cfg := config.Config{Upstream: "http://localhost"}
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach backend")
	}), nil, cfg)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if got := string(body); got == "" {
		t.Error("expected error message in body")
	}
}

// NOTE: Full happy-path integration tests (with real OIDC tokens and impersonation
// header verification) are covered in proxy_test.go. The unit tests above focus on
// individual rejection paths that don't require constructing a real oidc.IDToken.
