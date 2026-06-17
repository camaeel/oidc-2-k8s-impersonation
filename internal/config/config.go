package config

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

func GetConfig() Config {
	return Config{Port: defaultPort}
}
