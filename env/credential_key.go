package env

import "strings"

// credentialSegments are underscore-separated tokens that mark a key as secret-like
// (OpenShell sandbox create --env warning semantics). Matching is whole-segment only.
var credentialSegments = []string{
	"TOKEN",
	"SECRET",
	"PASSWORD",
	"CREDENTIAL",
	"API_KEY",
	"ACCESS_KEY",
	"SECRET_KEY",
}

// LooksLikeCredential reports whether an environment variable name looks like a
// secret that should travel via providers, not plain --env injection.
//
// Matching is on underscore-separated segments (case-insensitive): DB_TOKEN matches,
// TOKENIZERS_PARALLELISM and PASSWORDLESS_LOGIN do not.
func LooksLikeCredential(key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	if IsPassthrough(key) {
		return false
	}
	upper := strings.ToUpper(key)
	for _, k := range KnownCredentialKeys {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	parts := strings.Split(upper, "_")
	for _, seg := range credentialSegments {
		want := strings.Split(seg, "_")
		if len(want) == 1 {
			for _, p := range parts {
				if p == want[0] {
					return true
				}
			}
			continue
		}
		// Multi-token segment (API_KEY): require consecutive parts.
		for i := 0; i+len(want) <= len(parts); i++ {
			match := true
			for j := range want {
				if parts[i+j] != want[j] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}
