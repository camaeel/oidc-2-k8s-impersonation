package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// NewOIDCVerifier performs OIDC provider discovery with retry logic and returns
// a configured IDTokenVerifier. It retries up to maxAttempts times with exponential
// backoff to handle slow identity provider startup (e.g. Dex).
// If audience is empty, client_id verification is skipped.
func NewOIDCVerifier(issuer, audience string) (*oidc.IDTokenVerifier, error) {
	const maxAttempts = 12

	var (
		provider *oidc.Provider
		err      error
	)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		provider, err = oidc.NewProvider(ctx, issuer)
		cancel()
		if err == nil {
			slog.Info("OIDC provider discovered", "issuer", issuer)
			break
		}
		slog.Warn("OIDC provider not ready, will retry",
			"attempt", attempt, "max", maxAttempts,
			"issuer", issuer, "error", err)
		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt*5) * time.Second)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider at %s after %d attempts: %w",
			issuer, maxAttempts, err)
	}

	// Configure verifier with audience/client id if provided.
	oidcCfg := &oidc.Config{ClientID: audience}
	if audience == "" {
		oidcCfg.SkipClientIDCheck = true
		slog.Warn("AUDIENCE not configured, skipping OIDC audience (client_id) verification")
	}


	return provider.Verifier(oidcCfg), nil
}
