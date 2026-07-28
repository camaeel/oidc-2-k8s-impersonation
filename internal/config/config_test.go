package config

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetFlagCommandLine replaces the global flag.CommandLine with a fresh
// ContinueOnError FlagSet and sets os.Args so that each sub-test can define
// and parse its own flags independently. Both are restored via t.Cleanup.
func resetFlagCommandLine(t *testing.T, args []string) {
	t.Helper()
	oldCL := flag.CommandLine
	oldArgs := os.Args
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	os.Args = args
	t.Cleanup(func() {
		flag.CommandLine = oldCL
		os.Args = oldArgs
	})
}

func TestPortEnvDefault(t *testing.T) {
	testCases := []struct {
		name     string
		envVal   string
		wantPort int
		wantErr  bool
	}{
		{
			name:     "no PORT env var returns defaultHttpPort",
			wantPort: defaultHttpPort,
		},
		{
			name:     "valid PORT env var is parsed",
			envVal:   "9090",
			wantPort: 9090,
		},
		{
			name:    "invalid PORT env var returns an error",
			envVal:  "notanumber",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envVal != "" {
				t.Setenv(portEnvVarName, tc.envVal)
			} else {
				os.Unsetenv(portEnvVarName)
			}

			got, err := portEnvDefault(portEnvVarName, defaultHttpPort)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantPort, got)
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	const (
		validUpstream = "https://k8s.example.com"
		validIssuer   = "https://issuer.example.com"
	)

	testCases := []struct {
		name    string
		args    []string
		envVars map[string]string
		want    Config
		wantErr bool
	}{
		{
			name: "defaults are applied when only required fields are provided",
			args: []string{"cmd",
				"--upstream=" + validUpstream,
				"--issuer=" + validIssuer,
			},
			want: Config{
				Port:              defaultHttpPort,
				ObservabilityPort: defaultObservabilityPort,
				Upstream:          validUpstream,
				Issuer:            validIssuer,
				GroupsClaim:       defaultGroupsClaim,
				UserClaim:         defaultUserClaim,
			},
		},
		{
			name: "all values set via flags",
			args: []string{"cmd",
				"--port=9090",
				"--upstream=" + validUpstream,
				"--issuer=" + validIssuer,
				"--audience=my-client",
				"--groups-claim=roles",
				"--user-claim=email",
				"--group-prefix=team:",
				"--add-group-prefix=system:",
			},
			want: Config{
				Port:              9090,
				ObservabilityPort: defaultObservabilityPort,
				Upstream:          validUpstream,
				Issuer:            validIssuer,
				Audience:          "my-client",
				GroupsClaim:       "roles",
				UserClaim:         "email",
				GroupPrefix:       "team:",
				AddGroupPrefix:    "system:",
			},
		},
		{
			name: "all values set via env vars",
			args: []string{"cmd"},
			envVars: map[string]string{
				"PORT":             "7070",
				"UPSTREAM":         validUpstream,
				"ISSUER":           validIssuer,
				"AUDIENCE":         "env-client",
				"GROUPS_CLAIM":     "roles",
				"USER_CLAIM":       "email",
				"GROUP_PREFIX":     "env-prefix:",
				"ADD_GROUP_PREFIX": "env-append:",
			},
			want: Config{
				Port:              7070,
				ObservabilityPort: defaultObservabilityPort,
				Upstream:          validUpstream,
				Issuer:            validIssuer,
				Audience:          "env-client",
				GroupsClaim:       "roles",
				UserClaim:         "email",
				GroupPrefix:       "env-prefix:",
				AddGroupPrefix:    "env-append:",
			},
		},
		{
			name: "flag value takes precedence over env var",
			args: []string{"cmd",
				"--port=8888",
				"--upstream=https://flag-wins.example.com",
				"--issuer=" + validIssuer,
			},
			envVars: map[string]string{
				"PORT":     "1111",
				"UPSTREAM": "https://env-loses.example.com",
			},
			want: Config{
				Port:              8888,
				ObservabilityPort: defaultObservabilityPort,
				Upstream:          "https://flag-wins.example.com",
				Issuer:            validIssuer,
				GroupsClaim:       defaultGroupsClaim,
				UserClaim:         defaultUserClaim,
			},
		},
		{
			name:    "missing upstream returns validation error",
			args:    []string{"cmd", "--issuer=" + validIssuer},
			wantErr: true,
		},
		{
			name:    "missing issuer returns validation error",
			args:    []string{"cmd", "--upstream=" + validUpstream},
			wantErr: true,
		},
		{
			name:    "upstream with path returns validation error",
			args:    []string{"cmd", "--upstream=https://k8s.example.com/some/path", "--issuer=" + validIssuer},
			wantErr: true,
		},
		{
			name:    "upstream with unsupported scheme returns validation error",
			args:    []string{"cmd", "--upstream=ftp://k8s.example.com", "--issuer=" + validIssuer},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetFlagCommandLine(t, tc.args)
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}

			got, err := GetConfig()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
