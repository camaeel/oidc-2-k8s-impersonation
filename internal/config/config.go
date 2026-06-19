package config

import (
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
)

const (
	defaultHttpPort    = 8080
	defaultGroupsClaim = "groups"
	defaultUserClaim   = "sub"

	portEnvVarName           = "PORT"
	upstreamEnvVarName       = "UPSTREAM"
	issuerEnvVarName         = "ISSUER"
	audienceEnvVarName       = "AUDIENCE"
	groupsClaimEnvVarName    = "GROUPS_CLAIM"
	userClaimEnvVarName      = "USER_CLAIM"
	groupsPrefixEnvVarName   = "GROUP_PREFIX"
	addGroupPrefixEnvVarName = "ADD_GROUP_PREFIX"
)

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
	GroupPrefix    string // only groups that start with this prefix will be proxied
	AddGroupPrefix string // prefix to add to groups when creating Impersonate-Group headers
}

// GetConfig parses --flags (with env vars as defaults) and returns a Config.
//
// Each flag falls back to its corresponding env var when not supplied:
//
//	-port          PORT          (default: 8080)
//	-upstream      UPSTREAM
//	-issuer        ISSUER
//	-audience      AUDIENCE
//	-groups-claim  GROUPS_CLAIM
//	-user-claim    USER_CLAIM
//	-group-prefix  GROUP_PREFIX
//	-append-prefix APPEND_PREFIX
//
// Log level is configured separately via the LOG_LEVEL env var (see logging package).
func GetConfig() (Config, error) {
	defaultPortEnv, err := portEnvDefault()
	if err != nil {
		return Config{}, fmt.Errorf("invalid port in PORT env var: %w", err)
	}

	defaultGroupsEnv := os.Getenv(groupsClaimEnvVarName)
	if defaultGroupsEnv == "" {
		defaultGroupsEnv = defaultGroupsClaim
	}

	defaultUserEnv := os.Getenv(userClaimEnvVarName)
	if defaultUserEnv == "" {
		defaultUserEnv = defaultUserClaim
	}

	port := flag.Int("port", defaultPortEnv, "listening `port`")
	upstream := flag.String("upstream", os.Getenv(upstreamEnvVarName), "upstream base `URL` (required)")
	issuer := flag.String("issuer", os.Getenv(issuerEnvVarName), "OIDC issuer `URL` for token validation")
	audience := flag.String("audience", os.Getenv(audienceEnvVarName), "expected audience / client-id in the token")
	groupsClaim := flag.String("groups-claim", defaultGroupsEnv, "JWT claim name that holds group memberships")
	userClaim := flag.String("user-claim", defaultUserEnv, "JWT claim name that holds the user identifier")
	groupPrefix := flag.String("group-prefix", os.Getenv(groupsPrefixEnvVarName), "only proxy groups with this prefix (empty = all)")
	addGroupPrefix := flag.String("add-group-prefix", os.Getenv(addGroupPrefixEnvVarName), "prefix prepended to each group in Impersonate-Group header")

	flag.Parse()

	cfg := Config{
		Port:           *port,
		Upstream:       *upstream,
		Issuer:         *issuer,
		Audience:       *audience,
		GroupsClaim:    *groupsClaim,
		UserClaim:      *userClaim,
		GroupPrefix:    *groupPrefix,
		AddGroupPrefix: *addGroupPrefix,
	}

	err = validateConfig(cfg)
	if err != nil {
		return Config{}, err
	}

	slog.Debug("starting with config",
		"port", cfg.Port,
		"upstream", cfg.Upstream,
		"issuer", cfg.Issuer,
		"audience", cfg.Audience,
		"user_claim", cfg.UserClaim,
		"groups_claim", cfg.GroupsClaim,
		"group_prefix", cfg.GroupPrefix,
		"add_group_prefix", cfg.AddGroupPrefix,
	)

	return cfg, nil
}

func portEnvDefault() (int, error) {
	portStr := os.Getenv(portEnvVarName)
	if portStr == "" {
		return defaultHttpPort, nil
	}
	return strconv.Atoi(portStr)
}

func validateConfig(cfg Config) error {
	if cfg.Upstream == "" {
		return fmt.Errorf("upstream URL is required")
	}
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}

	if upstream.Path != "" && upstream.Path != "/" {
		return fmt.Errorf("upstream URL must not contain a path")
	}

	if upstream.Scheme != "http" && upstream.Scheme != "https" {
		return fmt.Errorf("upstream URL must have http or https scheme")
	}

	if cfg.Issuer == "" {
		return fmt.Errorf("issuer URL is required")
	}

	_, err = url.Parse(cfg.Issuer)
	if err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}

	return nil
}
