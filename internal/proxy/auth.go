package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
)

// extractBearerToken extracts the token from an Authorization header value.
// Returns the raw token string and nil error on success.
// Returns an error if the header is present but not a Bearer token.
// Returns ("", nil) if the header is empty.
func extractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", nil
	}

	token := strings.TrimSpace(authHeader)
	if len(token) >= 6 && strings.EqualFold(token[:6], "bearer") {
		token = strings.TrimSpace(token[6:])
		if token == "" {
			return "", errors.New("bearer token is empty")
		}
		return token, nil
	}

	return "", fmt.Errorf("authorization header is not Bearer")
}

// AuthMiddleware wraps a handler with OIDC authentication and impersonation header logic.
// If verifier is nil, it will reject requests with Authorization headers and pass
// unauthenticated requests through (stripping any impersonation headers).
func AuthMiddleware(next http.Handler, verifier TokenVerifier, cfg config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			next.ServeHTTP(w, r)
			return
		}

		// Authorization present. Parse Bearer token.
		token, err := extractBearerToken(auth)
		if err != nil {
			reject("unauthorized", http.StatusUnauthorized, "detail", err.Error())
			return
		}
		slog.Debug("bearer token extracted", "token_len", len(token))

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

		// Extract groups and filter/prefix them.
		groups := extractGroups(claims, cfg.GroupsClaim)
		slog.Debug("groups extracted from token", "claim", cfg.GroupsClaim, "groups", groups)

		impersonateGroups := filterGroups(groups, cfg.GroupPrefix, cfg.AddGroupPrefix)
		for _, g := range impersonateGroups {
			r.Header.Add("Impersonate-Group", g)
		}

		// Extract user claim and set Impersonate-User header if present.
		impersonateUser := extractUser(claims, cfg.UserClaim)
		if impersonateUser != "" {
			r.Header.Set("Impersonate-User", impersonateUser)
		}

		slog.Debug("proxying request with impersonation headers",
			"impersonate_user", impersonateUser,
			"impersonate_groups", impersonateGroups,
			"upstream", cfg.Upstream,
		)

		// Strip Authorization header before proxying.
		r.Header.Del("Authorization")

		next.ServeHTTP(w, r)
	})
}
