package main

import (
	"log/slog"
	"os"

	"github.com/camaeel/oidc-2-k8s-impersonation/internal/config"
	"github.com/camaeel/oidc-2-k8s-impersonation/internal/server"
	"github.com/camaeel/oidc-2-k8s-impersonation/internal/utils/logging"
)

func main() {
	logging.SetupLogging()

	cfg, err := config.GetConfig()
	if err != nil {
		slog.Error("failed to parse config", "error", err)
		os.Exit(1)
	}

	err = server.Start(cfg)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
	os.Exit(0)
}
