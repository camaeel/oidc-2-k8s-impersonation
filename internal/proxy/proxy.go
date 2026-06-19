package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

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
	var verifier TokenVerifier

	verifier, err = NewOIDCVerifier(cfg.Issuer, cfg.Audience)
	if err != nil {
		return nil, err
	}

	// Wrap the reverse proxy with authentication/impersonation middleware.
	return AuthMiddleware(rp, verifier, cfg), nil
}
