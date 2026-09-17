package env

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// ProfileHint suggests a provider create path for a credential env key.
type ProfileHint struct {
	ProviderType string
	Credential   string
}

// WarnCredentialEnv prints OpenShell-style warnings for plain --env secrets.
// hints maps env key → suggested provider profiles (may be empty).
func WarnCredentialEnv(w io.Writer, envMap map[string]string, hints map[string][]ProfileHint, suppress bool) {
	if suppress || len(envMap) == 0 {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	keys := make([]string, 0, len(envMap))
	for k := range envMap {
		if LooksLikeCredential(k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
	}
	// stable-ish order
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, key := range keys {
		fmt.Fprintf(w, "warn: %s looks like a credential passed as a plain environment variable.\n", key)
		fmt.Fprintf(w, "  The agent inside the sandbox can read this value directly.\n")
		hs := hints[key]
		if len(hs) == 0 {
			fmt.Fprintf(w, "  To hide it from the agent, use a provider instead of --env.\n")
		} else {
			fmt.Fprintf(w, "  To hide it from the agent, use a provider instead:\n")
			seen := map[string]struct{}{}
			for _, h := range hs {
				line := fmt.Sprintf("osg provider create --name my-%s --type %s --credential %s", h.ProviderType, h.ProviderType, key)
				if _, ok := seen[line]; ok {
					continue
				}
				seen[line] = struct{}{}
				fmt.Fprintf(w, "    %s\n", line)
			}
			fmt.Fprintf(w, "    osg sandbox create --provider my-<name> …\n")
		}
		fmt.Fprintf(w, "  See: docs/CREDENTIALS.md (use --no-credential-warnings to silence)\n\n")
	}
}

// HintKey matches KnownCredentialKeys / common aliases to profile ids.
func HintKey(key string) []ProfileHint {
	u := strings.ToUpper(strings.TrimSpace(key))
	switch u {
	case "CURSOR_API_KEY":
		return []ProfileHint{{ProviderType: "cursor", Credential: "api_key"}}
	case "GITHUB_TOKEN", "GH_TOKEN":
		return []ProfileHint{{ProviderType: "github", Credential: "token"}}
	case "ANTHROPIC_API_KEY", "CLAUDE_API_KEY":
		return []ProfileHint{{ProviderType: "claude-code", Credential: "api_key"}}
	case "NVIDIA_API_KEY", "NGC_API_KEY":
		return []ProfileHint{{ProviderType: "nvidia", Credential: "api_key"}}
	case "OPENAI_API_KEY":
		return []ProfileHint{{ProviderType: "codex", Credential: "api_key"}}
	default:
		return nil
	}
}
