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
		// Retry OIDC provider discovery so the proxy survives a slow Dex startup.
		const maxAttempts = 12
		var provider *oidc.Provider
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			provider, err = oidc.NewProvider(ctx, cfg.Issuer)
			cancel()
			if err == nil {
				slog.Info("OIDC provider discovered", "issuer", cfg.Issuer)
				break
			}
			slog.Warn("OIDC provider not ready, will retry",
				"attempt", attempt, "max", maxAttempts,
				"issuer", cfg.Issuer, "error", err)
			if attempt < maxAttempts {
				time.Sleep(time.Duration(attempt*5) * time.Second)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed to discover OIDC provider at %s after %d attempts: %w",
				cfg.Issuer, maxAttempts, err)
		}
		// Configure verifier with audience/client id if provided.
		oidcCfg := &oidc.Config{ClientID: cfg.Audience}
		verifier = provider.Verifier(oidcCfg)
		_ = oauth2.HTTPClient
	}

	// Top-level handler does authentication/impersonation header management
	// and then delegates to the reverse proxy.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("incoming request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "has_auth", r.Header.Get("Authorization") != "")

		// reject helper – always logs at Warn so it shows at every log level
		reject := func(msg string, status int, args ...any) {
			slog.Warn("request rejected", append([]any{"status", status, "reason", msg}, args...)...)
			http.Error(w, msg, status)
		}

		// Strip any existing impersonation headers from the incoming request.
		r.Header.Del("Impersonate-User")
		r.Header.Del("Impersonate-Group")

		auth := r.Header.Get("Authorization")

		if auth == "" {
			if verifier != nil {
				// Authorization required when OIDC verifier is configured.
				reject("unauthorized", http.StatusUnauthorized)
				return
			}
			// No verifier configured: just remove Authorization and proxy.
			r.Header.Del("Authorization")
			slog.Debug("no verifier configured, proxying unauthenticated request")
			rp.ServeHTTP(w, r)
			return
		}

		// Authorization present. Parse Bearer token.
		token := strings.TrimSpace(auth)
		if len(token) >= 6 && strings.EqualFold(token[:6], "bearer") {
			// remove 'Bearer' prefix (case-insensitive)
			token = strings.TrimSpace(token[6:])
			slog.Debug("bearer token extracted", "token_len", len(token))
		} else {
			reject("unauthorized", http.StatusUnauthorized, "detail", "authorization header is not Bearer")
			return
		}

		if verifier == nil {
			// Cannot validate token without an issuer configured.
			reject("unauthorized", http.StatusUnauthorized, "detail", "no OIDC verifier configured")
			return
		}

		vctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		idToken, err := verifier.Verify(vctx, token)
		if err != nil {
			reject("unauthorized", http.StatusUnauthorized, "error", err)
			return
		}
		slog.Debug("token verified", "subject", idToken.Subject, "issuer", idToken.Issuer, "expiry", idToken.Expiry)

		// Extract claims.
		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			reject("unauthorized", http.StatusUnauthorized, "error", err)
			return
		}
		slog.Debug("token claims parsed", "claims", claims)

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
			slog.Debug("groups extracted from token", "claim", cfg.GroupsClaim, "groups", groups)
		}

		// Filter groups by prefix and add impersonation headers.
		var impersonateGroups []string
		for _, g := range groups {
			if cfg.GroupPrefix == "" || strings.HasPrefix(g, cfg.GroupPrefix) {
				out := cfg.AppendPrefix + g
				r.Header.Add("Impersonate-Group", out)
				impersonateGroups = append(impersonateGroups, out)
			}
		}

		// Extract user claim and set Impersonate-User header if present.
		var impersonateUser string
		if cfg.UserClaim != "" {
			if uraw, ok := claims[cfg.UserClaim]; ok && uraw != nil {
				if us, ok := uraw.(string); ok && us != "" {
					r.Header.Set("Impersonate-User", us)
					impersonateUser = us
				}
			}
		}

		slog.Debug("proxying request with impersonation headers",
			"impersonate_user", impersonateUser,
			"impersonate_groups", impersonateGroups,
			"upstream", cfg.Upstream,
		)

		// Strip Authorization header before proxying.
		r.Header.Del("Authorization")

		rp.ServeHTTP(w, r)
	})

	return handler, nil
}
