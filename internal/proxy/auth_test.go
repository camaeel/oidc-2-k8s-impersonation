package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
)

// mockVerifier implements TokenVerifier for testing.
type mockVerifier struct {
	token *oidc.IDToken
	err   error
}

func (m *mockVerifier) Verify(_ context.Context, _ string) (*oidc.IDToken, error) {
	return m.token, m.err
}

func TestExtractBearerToken(t *testing.T) {
	testcases := []struct {
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

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractBearerToken(tc.authHeader)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantToken, got)
			}
		})
	}
}

func TestAuthMiddleware(t *testing.T) {
	testcases := []struct {
		name            string
		verifier        TokenVerifier
		authHeader      string
		impersonateUser string
		impersonateGrp  string
		wantStatus      int
		wantProxied     bool
	}{
		{
			name:            "no auth, no verifier → proxied, impersonation stripped",
			verifier:        nil,
			authHeader:      "",
			impersonateUser: "evil",
			impersonateGrp:  "admin",
			wantStatus:      http.StatusOK,
			wantProxied:     true,
		},
		{
			name:        "no auth, with verifier → 401",
			verifier:    &mockVerifier{},
			authHeader:  "",
			wantStatus:  http.StatusUnauthorized,
			wantProxied: false,
		},
		{
			name:        "invalid bearer scheme → 401",
			verifier:    &mockVerifier{},
			authHeader:  "Basic dXNlcjpwYXNz",
			wantStatus:  http.StatusUnauthorized,
			wantProxied: false,
		},
		{
			name:        "verify fails → 401",
			verifier:    &mockVerifier{err: context.DeadlineExceeded},
			authHeader:  "Bearer some-token",
			wantStatus:  http.StatusUnauthorized,
			wantProxied: false,
		},
		{
			name:        "auth present, no verifier → 401",
			verifier:    nil,
			authHeader:  "Bearer some-token",
			wantStatus:  http.StatusUnauthorized,
			wantProxied: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			proxied := false
			var receivedHeaders http.Header

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxied = true
				receivedHeaders = r.Header.Clone()
				w.WriteHeader(http.StatusOK)
			})

			handler := AuthMiddleware(next, tc.verifier, config.Config{Upstream: "http://localhost"})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			if tc.impersonateUser != "" {
				req.Header.Set("Impersonate-User", tc.impersonateUser)
			}
			if tc.impersonateGrp != "" {
				req.Header.Set("Impersonate-Group", tc.impersonateGrp)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)
			assert.Equal(t, tc.wantProxied, proxied)

			if tc.wantProxied {
				assert.Empty(t, receivedHeaders.Get("Impersonate-User"), "Impersonate-User should be stripped")
				assert.Empty(t, receivedHeaders.Get("Impersonate-Group"), "Impersonate-Group should be stripped")
			}
		})
	}
}
