package proxy

import (
	"reflect"
	"testing"
)

func TestExtractGroups(t *testing.T) {
	tests := []struct {
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
			name:        "claim is []interface{} of strings",
			claims:      map[string]interface{}{"groups": []interface{}{"admin", "dev", "ops"}},
			groupsClaim: "groups",
			want:        []string{"admin", "dev", "ops"},
		},
		{
			name:        "claim is []interface{} with non-string elements skipped",
			claims:      map[string]interface{}{"groups": []interface{}{"admin", 42, "ops"}},
			groupsClaim: "groups",
			want:        []string{"admin", "ops"},
		},
		{
			name:        "claim is []string",
			claims:      map[string]interface{}{"groups": []string{"a", "b"}},
			groupsClaim: "groups",
			want:        []string{"a", "b"},
		},
		{
			name:        "claim is comma-separated string",
			claims:      map[string]interface{}{"groups": "admin, dev, ops"},
			groupsClaim: "groups",
			want:        []string{"admin", "dev", "ops"},
		},
		{
			name:        "claim is single string without commas",
			claims:      map[string]interface{}{"groups": "admin"},
			groupsClaim: "groups",
			want:        []string{"admin"},
		},
		{
			name:        "claim is empty string",
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGroups(tt.claims, tt.groupsClaim)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractGroups() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterGroups(t *testing.T) {
	tests := []struct {
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterGroups(tt.groups, tt.filterPrefix, tt.addPrefix)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterGroups() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractUser(t *testing.T) {
	tests := []struct {
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
			name:      "claim is valid string",
			claims:    map[string]interface{}{"sub": "alice@example.com"},
			userClaim: "sub",
			want:      "alice@example.com",
		},
		{
			name:      "claim is non-string type",
			claims:    map[string]interface{}{"sub": 12345},
			userClaim: "sub",
			want:      "",
		},
		{
			name:      "custom claim name (email)",
			claims:    map[string]interface{}{"email": "bob@test.org"},
			userClaim: "email",
			want:      "bob@test.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractUser(tt.claims, tt.userClaim)
			if got != tt.want {
				t.Errorf("extractUser() = %q, want %q", got, tt.want)
			}
		})
	}
}
