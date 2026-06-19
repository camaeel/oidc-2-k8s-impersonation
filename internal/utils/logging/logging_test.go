package logging

import (
	"bytes"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupLogging(t *testing.T) {
	testCases := []struct {
		name         string
		logLevelEnv  string
		setEnv       bool
		testLogLevel slog.Level
		shouldLog    bool
	}{
		{
			name:         "with INFO level",
			logLevelEnv:  "INFO",
			setEnv:       true,
			testLogLevel: slog.LevelInfo,
			shouldLog:    true,
		},
		{
			name:         "with default level when env not set",
			setEnv:       false,
			testLogLevel: slog.LevelInfo,
			shouldLog:    true,
		},
		{
			name:         "INFO level should not log DEBUG messages",
			logLevelEnv:  "INFO",
			setEnv:       true,
			testLogLevel: slog.LevelDebug,
			shouldLog:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			if tc.setEnv {
				require.NoError(t, os.Setenv(logLevelEnv, tc.logLevelEnv))
				defer func() {
					_ = os.Unsetenv(logLevelEnv)
				}()
			} else {
				_ = os.Unsetenv(logLevelEnv)
			}

			// Capture stdout to verify JSON output
			var buf bytes.Buffer
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			defer func() {
				os.Stdout = oldStdout
			}()

			// Execute
			SetupLogging()

			// Test logging at the specified level
			testMessage := "test log message"
			switch tc.testLogLevel {
			case slog.LevelDebug:
				slog.Debug(testMessage)
			case slog.LevelInfo:
				slog.Info(testMessage)
			case slog.LevelWarn:
				slog.Warn(testMessage)
			case slog.LevelError:
				slog.Error(testMessage)
			}

			// Close writer and capture output
			_ = w.Close()
			_, err := buf.ReadFrom(r)
			require.NoError(t, err)
			output := buf.String()

			// Assert
			if tc.shouldLog {
				assert.Contains(t, output, testMessage, "Expected log message to be present")
			} else {
				assert.NotContains(t, output, testMessage, "Expected log message to be filtered out by log level")
			}
		})
	}
}
