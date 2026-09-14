package policy

import "fmt"

// MergeGlobal overlays gateway-global policy onto a sandbox document.
// Global network.allow entries are prepended (matched first). Top-level
// binaries and rego_path from global fill in when sandbox leaves them empty;
// sandbox non-empty fields win for binaries/rego_path.
func MergeGlobal(sandbox, global Document) (Document, error) {
	if global.Version == 0 {
		global.Version = 1
	}
	if err := global.Validate(); err != nil {
		return Document{}, fmt.Errorf("global policy: %w", err)
	}
	out := sandbox
	if out.Version == 0 {
		out.Version = 1
	}
	if global.Network != nil && len(global.Network.Allow) > 0 {
		if out.Network == nil {
			out.Network = &Network{Default: "deny"}
		}
		merged := make([]AllowRule, 0, len(global.Network.Allow)+len(out.Network.Allow))
		merged = append(merged, global.Network.Allow...)
		merged = append(merged, out.Network.Allow...)
		out.Network.Allow = merged
		if out.Network.Default == "" {
			out.Network.Default = "deny"
		}
	}
	if len(out.Binaries) == 0 && len(global.Binaries) > 0 {
		out.Binaries = append([]string{}, global.Binaries...)
	}
	if out.RegoPath == "" && global.RegoPath != "" {
		out.RegoPath = global.RegoPath
	}
	if err := out.Validate(); err != nil {
		return Document{}, fmt.Errorf("merged policy: %w", err)
	}
	return out, nil
}
