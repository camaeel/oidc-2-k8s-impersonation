package dummy_oidc_server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

// DummyOIDCServer provides a mock OpenID Connect server for Vault testing
type DummyOIDCServer struct {
	Server     *http.Server
	Listener   net.Listener
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Issuer     string // External issuer URL for Docker containers
	Audience   string
	Subject    string
	Nickname   string
	KeyID      string
	Port       int
}

// OIDCDiscoveryResponse represents the OIDC discovery document
type OIDCDiscoveryResponse struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// JWKSResponse represents the JSON Web Key Set
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// SetupDummyOIDCServer creates a new mock OIDC server for Vault testing
// This server binds to 0.0.0.0 so it can be accessed from Docker containers
func SetupDummyOIDCServer(t *testing.T) (*DummyOIDCServer, error) {
	t.Helper()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	dummy := &DummyOIDCServer{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Audience:   "https://local.example.com",
		Subject:    "test-user-123",
		Nickname:   "testuser",
		KeyID:      "test-key-1",
	}

	mux := http.NewServeMux()

	// OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := OIDCDiscoveryResponse{
			Issuer:                           dummy.Issuer,
			AuthorizationEndpoint:            dummy.Issuer + "/oauth/authorize",
			TokenEndpoint:                    dummy.Issuer + "/oauth/token",
			UserinfoEndpoint:                 dummy.Issuer + "/oauth/userinfo",
			JwksURI:                          dummy.Issuer + "/.well-known/jwks.json",
			ScopesSupported:                  []string{"openid", "profile", "email", "api"},
			ResponseTypesSupported:           []string{"code", "token", "id_token"},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(discovery); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// JWKS endpoint (for Vault to verify JWT signatures)
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks := JWKSResponse{
			Keys: []JWK{dummy.getJWK()},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// Catch-all handler for unmatched paths
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "404 page not found", http.StatusNotFound)
	})

	// Listen on 0.0.0.0 with a random port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	dummy.Listener = listener
	dummy.Port = listener.Addr().(*net.TCPAddr).Port
	// Use localhost since Vault test server is in the same process
	dummy.Issuer = fmt.Sprintf("http://127.0.0.1:%d", dummy.Port)
	// If we need external access from Docker, use: fmt.Sprintf("http://%s:%d", daemonHost, dummy.Port)

	dummy.Server = &http.Server{
		Handler: mux,
	}

	// Start server in background
	go func() {
		err := dummy.Server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
	}()

	t.Cleanup(func() {
		dummy.Close()
	})
	return dummy, nil
}

// getJWK converts the public key to JWK format for JWKS endpoint
func (d *DummyOIDCServer) getJWK() JWK {
	// Encode public key components
	nBytes := d.PublicKey.N.Bytes()
	eBytes := big.NewInt(int64(d.PublicKey.E)).Bytes()

	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: d.KeyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

// GenerateJWT creates a signed JWT token for testing
func (d *DummyOIDCServer) GenerateJWT(additionalClaims map[string]interface{}) (string, error) {
	now := time.Now()

	// Create custom claims map that includes standard claims and additional claims
	allClaims := make(map[string]interface{})
	allClaims["iss"] = d.Issuer
	allClaims["sub"] = d.Subject
	allClaims["aud"] = d.Audience
	allClaims["exp"] = now.Add(1 * time.Hour).Unix()
	allClaims["iat"] = now.Unix()
	allClaims["nbf"] = now.Unix()
	allClaims["nickname"] = d.Nickname

	// Add any additional claims
	for k, v := range additionalClaims {
		allClaims[k] = v
	}

	// Create signer
	signerOptions := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", d.KeyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: d.PrivateKey}, signerOptions)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// Create and sign the token
	builder := jwt.Signed(signer).Claims(allClaims)
	tokenString, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// GetCACert returns an empty CA cert (not needed for HTTP test scenarios)
func (d *DummyOIDCServer) GetCACert() string {
	return ""
}

// GetCACertPEM returns a PEM-encoded certificate if needed for TLS verification
func (d *DummyOIDCServer) GetCACertPEM() (string, error) {
	// Create a self-signed certificate for the public key
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, d.PublicKey, d.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return string(pemCert), nil
}

// Close shuts down the mock server
func (d *DummyOIDCServer) Close() {
	if d.Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.Server.Shutdown(ctx)
	}
}
