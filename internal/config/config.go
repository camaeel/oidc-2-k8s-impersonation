package config

import (
	"log/slog"
	"os"
	"strconv"
)

const defaultPort = 8080

type Config struct {
	Port     int
	Upstream string
	// OIDC issuer URL (e.g. https://accounts.example.com/)
	Issuer string
	// Expected audience / client id for token verification
	Audience string

	// Claims configuration
	GroupsClaim string // name of the claim that contains groups (expected to be a list)
	UserClaim   string // name of the claim that contains the user name

	// Filtering / prefixing
	GroupPrefix  string // only groups that start with this prefix will be proxied
	AppendPrefix string // prefix to add to groups when creating Impersonate-Group headers
}

// GetConfig builds a Config from environment variables with sensible defaults.
//
// Supported environment variables:
//
//	PORT          – listening port (default: 8080)
//	UPSTREAM      – upstream base URL (required)
//	ISSUER        – OIDC issuer URL for token validation
//	AUDIENCE      – expected audience / client-id in the token
//	GROUPS_CLAIM  – JWT claim name that holds group memberships
//	USER_CLAIM    – JWT claim name that holds the user identifier
//	GROUP_PREFIX  – only proxy groups with this prefix (empty = all)
//	APPEND_PREFIX – string prepended to each group in Impersonate-Group header
func GetConfig() Config {
	port := defaultPort
	if raw := os.Getenv("PORT"); raw != "" {
		if p, err := strconv.Atoi(raw); err == nil {
			port = p
		} else {
			slog.Warn("invalid PORT value, using default", "value", raw, "default", defaultPort)
		}
	}

	return Config{
		Port:         port,
		Upstream:     os.Getenv("UPSTREAM"),
		Issuer:       os.Getenv("ISSUER"),
		Audience:     os.Getenv("AUDIENCE"),
		GroupsClaim:  os.Getenv("GROUPS_CLAIM"),
		UserClaim:    os.Getenv("USER_CLAIM"),
		GroupPrefix:  os.Getenv("GROUP_PREFIX"),
		AppendPrefix: os.Getenv("APPEND_PREFIX"),
	}
}
