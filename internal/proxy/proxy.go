package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
)

// NewReverseProxy returns an http.Handler that forwards requests to the provided target
// leaving the request path and query intact. It preserves the original Host header.
// If cfg.Issuer is set, the handler will validate incoming Authorization: Bearer tokens
// using the OIDC provider discovered at cfg.Issuer. If validation succeeds, groups and
// user claims will be extracted and converted into Impersonate-Group and Impersonate-User
// headers according to cfg.
func NewReverseProxy(cfg config.Config) (http.Handler, error) {
	u, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL %q: %w", cfg.Upstream, err)
	}

	// ReverseProxy using the new Rewrite API (Director is deprecated).
	rp := &httputil.ReverseProxy{
		Rewrite: func(preq *httputil.ProxyRequest) {
			// Route to the target and preserve the original Host header.
			preq.SetURL(u)
			preq.Out.Host = preq.In.Host
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			slog.Error("reverse proxy error", "error", err)
			http.Error(rw, "bad gateway", http.StatusBadGateway)
		},
	}

	// Prepare OIDC verifier if issuer provided.
	var verifier *oidc.IDTokenVerifier
	if cfg.Issuer != "" {
		// Use a short timeout for provider discovery.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		provider, err := oidc.NewProvider(ctx, cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to discover OIDC provider at %s: %w", cfg.Issuer, err)
		}
		// Configure verifier with audience/client id if provided.
		oidcCfg := &oidc.Config{ClientID: cfg.Audience}
		verifier = provider.Verifier(oidcCfg)

		// Ensure the provider's HTTP client uses the oauth2 package's default
		// token source configuration (no token exchange here, just verification).
		_ = oauth2.HTTPClient
	}

	// Top-level handler does authentication/impersonation header management
	// and then delegates to the reverse proxy.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip any existing impersonation headers from the incoming request.
		r.Header.Del("Impersonate-User")
		r.Header.Del("Impersonate-Group")

		auth := r.Header.Get("Authorization")

		if auth == "" {
			if verifier != nil {
				// Authorization required when OIDC verifier is configured.
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			// No verifier configured: just remove Authorization and proxy.
			r.Header.Del("Authorization")
			rp.ServeHTTP(w, r)
			return
		}

		// Authorization present. Parse Bearer token.
		token := strings.TrimSpace(auth)
		if len(token) >= 6 && strings.EqualFold(token[:6], "bearer") {
			// remove 'Bearer' prefix (case-insensitive)
			token = strings.TrimSpace(token[6:])
		} else {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if verifier == nil {
			// Cannot validate token without an issuer configured.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		vctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		idToken, err := verifier.Verify(vctx, token)
		if err != nil {
			slog.Warn("token verification failed", "error", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract claims.
		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			slog.Warn("failed to parse token claims", "error", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract groups claim (expected to be a list). Be permissive with formats.
		var groups []string
		if cfg.GroupsClaim != "" {
			if raw, ok := claims[cfg.GroupsClaim]; ok && raw != nil {
				switch v := raw.(type) {
				case []interface{}:
					for _, it := range v {
						if s, ok := it.(string); ok {
							groups = append(groups, s)
						}
					}
				case []string:
					groups = append(groups, v...)
				case string:
					// single string (comma separated?) – split on commas
					for _, part := range strings.Split(v, ",") {
						part = strings.TrimSpace(part)
						if part != "" {
							groups = append(groups, part)
						}
					}
				}
			}
		}

		// Filter groups by prefix and add impersonation headers.
		for _, g := range groups {
			if cfg.GroupPrefix == "" || strings.HasPrefix(g, cfg.GroupPrefix) {
				out := cfg.AppendPrefix + g
				r.Header.Add("Impersonate-Group", out)
			}
		}

		// Extract user claim and set Impersonate-User header if present.
		if cfg.UserClaim != "" {
			if uraw, ok := claims[cfg.UserClaim]; ok && uraw != nil {
				if us, ok := uraw.(string); ok && us != "" {
					r.Header.Set("Impersonate-User", us)
				}
			}
		}

		// Strip Authorization header before proxying.
		r.Header.Del("Authorization")

		rp.ServeHTTP(w, r)
	})

	return handler, nil
}
