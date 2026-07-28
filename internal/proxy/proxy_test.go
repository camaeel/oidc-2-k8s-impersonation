package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
	dummy_oidc_server "github.com/camaeel/oidc-2-k8s-impersonation/internal/dummy_oidc_server"
)

func TestNewReverseProxy(t *testing.T) {
	testcases := []struct {
		name           string
		cfgFn          func(backendURL, issuerURL string) config.Config
		requestHeaders map[string]string
		tokenClaims    map[string]interface{}
		wantErr        bool
		reqPath        string
		wantBody       string
		wantStatus     int
	}{
		{
			name: "forwards authenticated request with impersonation",
			cfgFn: func(backendURL, issuerURL string) config.Config {
				return config.Config{
					Upstream:    backendURL,
					Issuer:      issuerURL,
					Audience:    "",
					GroupsClaim: "groups",
					UserClaim:   "sub",
					GroupPrefix: "",
				}
			},
			tokenClaims: map[string]interface{}{
				"sub":    "alice@example.com",
				"groups": []interface{}{"team-a", "team-b"},
			},
			reqPath:    "/api/v1/pods",
			wantBody:   "hello-backend",
			wantStatus: http.StatusOK,
		},
		{
			name: "rejects request without auth when verifier is configured",
			cfgFn: func(backendURL, issuerURL string) config.Config {
				return config.Config{
					Upstream:    backendURL,
					Issuer:      issuerURL,
					GroupsClaim: "groups",
					UserClaim:   "sub",
				}
			},
			tokenClaims: nil, // no token → no Authorization header
			reqPath:     "/api/v1/pods",
			wantStatus:  http.StatusUnauthorized,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Start dummy OIDC provider.
			oidcSrv, err := dummy_oidc_server.SetupDummyOIDCServer(t)
			require.NoError(t, err)

			// Start backend that echoes a fixed response.
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("hello-backend"))
			}))
			defer backend.Close()

			cfg := tc.cfgFn(backend.URL, oidcSrv.Issuer)
			h, err := NewReverseProxy(cfg)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, tc.reqPath, nil)

			// Add Authorization header with a signed token if claims are provided.
			if tc.tokenClaims != nil {
				token, err := oidcSrv.GenerateJWT(tc.tokenClaims)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+token)
			}

			// Add any extra request headers.
			for k, v := range tc.requestHeaders {
				req.Header.Set(k, v)
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)
			if tc.wantBody != "" {
				b, _ := io.ReadAll(rec.Body)
				assert.Equal(t, tc.wantBody, string(b))
			}
		})
	}
}
