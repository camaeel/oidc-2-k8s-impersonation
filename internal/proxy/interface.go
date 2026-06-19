package proxy

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
)

// TokenVerifier abstracts OIDC token verification for testing.
type TokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}
