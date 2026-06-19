package main

import (
	"log/slog"
	"os"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
	"github.com/camaeel/oidc-2-k8s-impersonation/internal/server"
	"github.com/camaeel/oidc-2-k8s-impersonation/internal/utils/logging"
)

func main() {
	// Configure log level via LOG_LEVEL env var (debug|info|warn|error).
	// Defaults to "info".
	logging.SetupLogging()

	cfg := config.GetConfig()
	slog.Debug("starting with config",
		"port", cfg.Port,
		"upstream", cfg.Upstream,
		"issuer", cfg.Issuer,
		"audience", cfg.Audience,
		"user_claim", cfg.UserClaim,
		"groups_claim", cfg.GroupsClaim,
		"group_prefix", cfg.GroupPrefix,
		"append_prefix", cfg.AppendPrefix,
	)

	err := server.Start(cfg)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
	os.Exit(0)
}
