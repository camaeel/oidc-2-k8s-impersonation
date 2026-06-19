package proxy

import "strings"

// extractGroups pulls groups from claims based on the claim name.
// Handles []interface{}, []string, and comma-separated string formats.
func extractGroups(claims map[string]interface{}, groupsClaim string) []string {
	if groupsClaim == "" {
		return nil
	}
	raw, ok := claims[groupsClaim]
	if !ok || raw == nil {
		return nil
	}

	var groups []string
	switch v := raw.(type) {
	case []interface{}:
		for _, it := range v {
			if s, ok := it.(string); ok {
				groups = append(groups, s)
			}
		}
	case []string:
		groups = append(groups, v...)
	case string:
		// single string (comma separated?) – split on commas
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				groups = append(groups, part)
			}
		}
	}
	return groups
}

// filterGroups filters groups by prefix and prepends addPrefix to each matching group.
// If filterPrefix is empty, all groups pass through.
func filterGroups(groups []string, filterPrefix, addPrefix string) []string {
	var result []string
	for _, g := range groups {
		if filterPrefix == "" || strings.HasPrefix(g, filterPrefix) {
			result = append(result, addPrefix+g)
		}
	}
	return result
}

// extractUser pulls the user identifier from the claims map using the given claim name.
// Returns empty string if not found or not a string.
func extractUser(claims map[string]interface{}, userClaim string) string {
	if userClaim == "" {
		return ""
	}
	raw, ok := claims[userClaim]
	if !ok || raw == nil {
		return ""
	}
	if s, ok := raw.(string); ok {
		return s
	}
	return ""
}
