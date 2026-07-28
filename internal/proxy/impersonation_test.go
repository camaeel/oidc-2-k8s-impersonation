package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractGroups(t *testing.T) {
	testcases := []struct {
		name        string
		claims      map[string]interface{}
		groupsClaim string
		want        []string
	}{
		{
			name:        "empty claim name",
			claims:      map[string]interface{}{"groups": []interface{}{"a"}},
			groupsClaim: "",
			want:        nil,
		},
		{
			name:        "claim not present",
			claims:      map[string]interface{}{},
			groupsClaim: "groups",
			want:        nil,
		},
		{
			name:        "claim is nil",
			claims:      map[string]interface{}{"groups": nil},
			groupsClaim: "groups",
			want:        nil,
		},
		{
			name:        "[]interface{} of strings",
			claims:      map[string]interface{}{"groups": []interface{}{"admin", "dev", "ops"}},
			groupsClaim: "groups",
			want:        []string{"admin", "dev", "ops"},
		},
		{
			name:        "[]interface{} with non-string skipped",
			claims:      map[string]interface{}{"groups": []interface{}{"admin", 42, "ops"}},
			groupsClaim: "groups",
			want:        []string{"admin", "ops"},
		},
		{
			name:        "[]string",
			claims:      map[string]interface{}{"groups": []string{"a", "b"}},
			groupsClaim: "groups",
			want:        []string{"a", "b"},
		},
		{
			name:        "comma-separated string",
			claims:      map[string]interface{}{"groups": "admin, dev, ops"},
			groupsClaim: "groups",
			want:        []string{"admin", "dev", "ops"},
		},
		{
			name:        "single string without commas",
			claims:      map[string]interface{}{"groups": "admin"},
			groupsClaim: "groups",
			want:        []string{"admin"},
		},
		{
			name:        "empty string",
			claims:      map[string]interface{}{"groups": ""},
			groupsClaim: "groups",
			want:        nil,
		},
		{
			name:        "custom claim name",
			claims:      map[string]interface{}{"roles": []interface{}{"editor"}},
			groupsClaim: "roles",
			want:        []string{"editor"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractGroups(tc.claims, tc.groupsClaim)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFilterGroups(t *testing.T) {
	testcases := []struct {
		name         string
		groups       []string
		filterPrefix string
		addPrefix    string
		want         []string
	}{
		{
			name:         "no filter prefix passes all",
			groups:       []string{"admin", "dev", "ops"},
			filterPrefix: "",
			addPrefix:    "",
			want:         []string{"admin", "dev", "ops"},
		},
		{
			name:         "filter by prefix",
			groups:       []string{"team:alpha", "team:beta", "other"},
			filterPrefix: "team:",
			addPrefix:    "",
			want:         []string{"team:alpha", "team:beta"},
		},
		{
			name:         "add prefix to results",
			groups:       []string{"admin", "dev"},
			filterPrefix: "",
			addPrefix:    "oidc:",
			want:         []string{"oidc:admin", "oidc:dev"},
		},
		{
			name:         "filter and add prefix combined",
			groups:       []string{"k8s:admin", "k8s:dev", "other"},
			filterPrefix: "k8s:",
			addPrefix:    "impersonate:",
			want:         []string{"impersonate:k8s:admin", "impersonate:k8s:dev"},
		},
		{
			name:         "no groups match filter",
			groups:       []string{"admin", "dev"},
			filterPrefix: "team:",
			addPrefix:    "",
			want:         nil,
		},
		{
			name:         "nil input",
			groups:       nil,
			filterPrefix: "",
			addPrefix:    "",
			want:         nil,
		},
		{
			name:         "empty input",
			groups:       []string{},
			filterPrefix: "",
			addPrefix:    "",
			want:         nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterGroups(tc.groups, tc.filterPrefix, tc.addPrefix)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExtractUser(t *testing.T) {
	testcases := []struct {
		name      string
		claims    map[string]interface{}
		userClaim string
		want      string
	}{
		{
			name:      "empty claim name",
			claims:    map[string]interface{}{"sub": "alice"},
			userClaim: "",
			want:      "",
		},
		{
			name:      "claim not present",
			claims:    map[string]interface{}{},
			userClaim: "sub",
			want:      "",
		},
		{
			name:      "claim is nil",
			claims:    map[string]interface{}{"sub": nil},
			userClaim: "sub",
			want:      "",
		},
		{
			name:      "valid string",
			claims:    map[string]interface{}{"sub": "alice@example.com"},
			userClaim: "sub",
			want:      "alice@example.com",
		},
		{
			name:      "non-string type",
			claims:    map[string]interface{}{"sub": 12345},
			userClaim: "sub",
			want:      "",
		},
		{
			name:      "custom claim (email)",
			claims:    map[string]interface{}{"email": "bob@test.org"},
			userClaim: "email",
			want:      "bob@test.org",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractUser(tc.claims, tc.userClaim)
			assert.Equal(t, tc.want, got)
		})
	}
}
