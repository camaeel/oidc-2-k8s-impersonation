package logging

import (
	"log/slog"
	"os"
)

const (
	logLevelEnv = "LOG_LEVEL"
)

func SetupLogging() {

	logLevel := os.Getenv(logLevelEnv)
	var parsedLevel slog.Level
	if logLevel != "" {
		err := parsedLevel.UnmarshalText([]byte(logLevel))
		if err != nil {
			slog.Warn("invalid log level in LOG_LEVEL env var, defaulting to INFO", "error", err)
		}
	} else {
		parsedLevel = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parsedLevel,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)
}
