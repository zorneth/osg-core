package policy

import "fmt"

// MergeGlobal overlays gateway-global policy onto a sandbox document.
// Global network_policies entries are prepended into the flattened allow
// list (matched first). Top-level binaries and rego_path from global fill
// in when sandbox leaves them empty; sandbox non-empty fields win.
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
	gAllows := global.NetworkAllows()
	if len(gAllows) > 0 {
		merged := make([]AllowRule, 0, len(gAllows)+len(out.NetworkAllows()))
		merged = append(merged, gAllows...)
		merged = append(merged, out.NetworkAllows()...)
		out.SetNetworkAllows(merged)
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
