// Package provider defines reusable provider profiles (catalog) and composition
// into sandbox effective policy (OpenShell-style level C).
package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zorneth/osg-core/policy"
	"gopkg.in/yaml.v3"
)

// Profile is a reusable provider type (catalog entry).
type Profile struct {
	ID          string           `yaml:"id" json:"id"`
	DisplayName string           `yaml:"display_name,omitempty" json:"display_name,omitempty"`
	Description string           `yaml:"description,omitempty" json:"description,omitempty"`
	Category    string           `yaml:"category,omitempty" json:"category,omitempty"`
	Endpoints   []policy.AllowRule `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	Binaries    []string         `yaml:"binaries,omitempty" json:"binaries,omitempty"`
	Credentials []Credential     `yaml:"credentials,omitempty" json:"credentials,omitempty"`
}

// Credential declares env keys for an attached instance.
// Values live in the gateway secret store; guests see osg:resolve:env:KEY
// placeholders unless InjectEnv is false (sidecar-only — Cursor OAuth path).
type Credential struct {
	Name      string   `yaml:"name" json:"name"`
	EnvVars   []string `yaml:"env_vars,omitempty" json:"env_vars,omitempty"`
	AuthStyle string   `yaml:"auth_style,omitempty" json:"auth_style,omitempty"` // reserved: bearer|header|basic|query|path
	Header    string   `yaml:"header_name,omitempty" json:"header_name,omitempty"`
	Required  bool     `yaml:"required,omitempty" json:"required,omitempty"`
	// InjectEnv controls guest env placeholders. nil/omitted → true.
	// Set false for agents that client-validate API keys (e.g. Cursor Agent).
	InjectEnv *bool `yaml:"inject_env,omitempty" json:"inject_env,omitempty"`
}

// Instance is a named provider on a gateway (env key refs only, no secret values).
type Instance struct {
	Name     string   `yaml:"name" json:"name"`
	Type     string   `yaml:"type" json:"type"` // profile id
	EnvVars  []string `yaml:"env_vars,omitempty" json:"env_vars,omitempty"`
}

// Validate checks a profile document.
func (p Profile) Validate() error {
	id := strings.TrimSpace(p.ID)
	if id == "" {
		return fmt.Errorf("provider profile: id required")
	}
	for i, ep := range p.Endpoints {
		if err := policy.ValidateAllowRule(fmt.Sprintf("endpoints[%d]", i), ep); err != nil {
			return fmt.Errorf("provider profile %q: %w", id, err)
		}
	}
	for i, c := range p.Credentials {
		if strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("provider profile %q: credentials[%d]: name required", id, i)
		}
		if len(c.EnvVars) == 0 {
			return fmt.Errorf("provider profile %q: credentials[%d]: env_vars required", id, i)
		}
	}
	return nil
}

// ParseYAML loads a profile from bytes.
func ParseYAML(b []byte) (Profile, error) {
	var p Profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Profile{}, fmt.Errorf("provider profile: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// LoadFile reads a profile YAML file.
func LoadFile(path string) (Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	return ParseYAML(b)
}

// LoadDir loads all *.yaml/*.yml profiles from a directory (non-recursive).
func LoadDir(dir string) (map[string]Profile, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]Profile{}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		p, err := LoadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out[p.ID] = p
	}
	return out, nil
}

// EnvKeys returns all credential env var names from the profile.
func (p Profile) EnvKeys() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, c := range p.Credentials {
		for _, k := range c.EnvVars {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	return out
}

// GuestEnvKeys returns credential env keys that should be injected into the guest
// as osg:resolve:env placeholders (excludes inject_env: false).
func (p Profile) GuestEnvKeys() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, c := range p.Credentials {
		if c.InjectEnv != nil && !*c.InjectEnv {
			continue
		}
		for _, k := range c.EnvVars {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	return out
}

// DiscoverEnvVars picks host env keys for a provider instance (OpenShell --from-existing).
// For each credential, the first non-empty env_vars entry wins. Required credentials
// with no value on the host return an error. Values are never returned — only key names.
func (p Profile) DiscoverEnvVars() ([]string, error) {
	var out []string
	seen := map[string]struct{}{}
	for _, c := range p.Credentials {
		found := ""
		for _, k := range c.EnvVars {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
				found = k
				break
			}
		}
		if found == "" {
			if c.Required {
				want := strings.Join(c.EnvVars, "|")
				return nil, fmt.Errorf("provider %q: credential %q missing on host (export %s)", p.ID, c.Name, want)
			}
			continue
		}
		if _, ok := seen[found]; ok {
			continue
		}
		seen[found] = struct{}{}
		out = append(out, found)
	}
	if len(out) == 0 && len(p.Credentials) > 0 {
		return nil, fmt.Errorf("provider %q: no credential env vars found on host", p.ID)
	}
	return out, nil
}

// Layer is one attached provider contribution.
type Layer struct {
	InstanceName string
	Profile      Profile
	EnvVars      []string // instance override; empty → profile defaults
}

// Compose merges base policy with attached provider layers into an effective document.
// When suppressProviders is true (gateway-global network active), layers are skipped.
func Compose(base policy.Document, layers []Layer, suppressProviders bool) policy.Document {
	out := base
	if out.Network == nil {
		out.Network = &policy.Network{Default: "deny"}
	} else {
		netCopy := *out.Network
		netCopy.Allow = append([]policy.AllowRule{}, out.Network.Allow...)
		out.Network = &netCopy
	}
	if out.Credentials == nil {
		out.Credentials = &policy.Credentials{}
	} else {
		credCopy := *out.Credentials
		credCopy.EnvAllow = append([]string{}, out.Credentials.EnvAllow...)
		out.Credentials = &credCopy
	}
	if suppressProviders {
		return out
	}
	envSeen := map[string]struct{}{}
	for _, k := range out.Credentials.EnvAllow {
		envSeen[k] = struct{}{}
	}
	for _, layer := range layers {
		p := layer.Profile
		keys := layer.EnvVars
		if len(keys) == 0 {
			keys = p.EnvKeys()
		}
		guestKeys := p.GuestEnvKeys()
		if len(layer.EnvVars) > 0 {
			// Instance override: still honor profile inject_env:false exclusions.
			omit := map[string]struct{}{}
			for _, c := range p.Credentials {
				if c.InjectEnv != nil && !*c.InjectEnv {
					for _, k := range c.EnvVars {
						omit[strings.TrimSpace(k)] = struct{}{}
					}
				}
			}
			guestKeys = nil
			for _, k := range keys {
				if _, skip := omit[k]; skip {
					continue
				}
				guestKeys = append(guestKeys, k)
			}
		}
		for i, ep := range p.Endpoints {
			rule := ep
			if rule.ID == "" {
				rule.ID = fmt.Sprintf("provider.%s.%d", layer.InstanceName, i)
			} else {
				rule.ID = fmt.Sprintf("provider.%s.%s", layer.InstanceName, rule.ID)
			}
			if len(rule.Binaries) == 0 && len(p.Binaries) > 0 {
				rule.Binaries = append([]string{}, p.Binaries...)
			}
			rule.CredentialKeys = append([]string{}, keys...)
			out.Network.Allow = append(out.Network.Allow, rule)
		}
		for _, k := range guestKeys {
			if _, ok := envSeen[k]; ok {
				continue
			}
			envSeen[k] = struct{}{}
			out.Credentials.EnvAllow = append(out.Credentials.EnvAllow, k)
		}
	}
	return out
}

// FindBuiltinDir locates a providers catalog directory (cwd or next to the executable).
func FindBuiltinDir() string {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "osg-cli", "providers"), filepath.Join(wd, "providers"))
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "providers"),
			filepath.Join(dir, "..", "providers"),
			filepath.Join(dir, "..", "osg-cli", "providers"),
		)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}
