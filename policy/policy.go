package policy

import (
	"fmt"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// Document is the canonical osg sandbox policy (product schema).
type Document struct {
	Version     int          `yaml:"version" json:"version"`
	Filesystem  *Filesystem  `yaml:"filesystem,omitempty" json:"filesystem,omitempty"`
	Process     *Process     `yaml:"process,omitempty" json:"process,omitempty"`
	Network     *Network     `yaml:"network,omitempty" json:"network,omitempty"`
	Display     *Display     `yaml:"display,omitempty" json:"display,omitempty"`
	Credentials *Credentials `yaml:"credentials,omitempty" json:"credentials,omitempty"`
}

// Filesystem is guest path policy + harden mode.
type Filesystem struct {
	IncludeWorkdir bool     `yaml:"include_workdir" json:"include_workdir"`
	Read           []string `yaml:"read,omitempty" json:"read,omitempty"`
	Write          []string `yaml:"write,omitempty" json:"write,omitempty"`
	// Mode: best_effort | required (Landlock / harden fail-closed).
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
}

// Process is sandbox process identity (omit to let the compute driver choose).
type Process struct {
	User  string `yaml:"user,omitempty" json:"user,omitempty"`
	Group string `yaml:"group,omitempty" json:"group,omitempty"`
}

// Network is default-deny egress with an allow list.
type Network struct {
	// Default must be "deny" (or empty → deny).
	Default string      `yaml:"default,omitempty" json:"default,omitempty"`
	Allow   []AllowRule `yaml:"allow,omitempty" json:"allow,omitempty"`
}

// AllowRule is one egress allow entry.
type AllowRule struct {
	ID       string   `yaml:"id,omitempty" json:"id,omitempty"`
	Host     string   `yaml:"host,omitempty" json:"host,omitempty"`
	Port     int      `yaml:"port,omitempty" json:"port,omitempty"`
	Ports    []int    `yaml:"ports,omitempty" json:"ports,omitempty"`
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`
}

// Display is the noVNC surface.
type Display struct {
	Mode    string `yaml:"mode,omitempty" json:"mode,omitempty"` // none | novnc
	Publish string `yaml:"publish,omitempty" json:"publish,omitempty"`
	Port    int    `yaml:"port,omitempty" json:"port,omitempty"`
	Auth    string `yaml:"auth,omitempty" json:"auth,omitempty"`
	Browser string `yaml:"browser,omitempty" json:"browser,omitempty"`
}

// Credentials controls host-side env injection.
type Credentials struct {
	EnvAllow    []string `yaml:"env_allow,omitempty" json:"env_allow,omitempty"`
	WriteToDisk bool     `yaml:"write_to_disk,omitempty" json:"write_to_disk,omitempty"`
}

// Load reads and parses a policy YAML file (ours or OpenShell-shaped).
func Load(path string) (Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	return Parse(b)
}

// Parse unmarshals policy YAML. OpenShell-shaped keys are imported automatically.
func Parse(data []byte) (Document, error) {
	if looksOpenShell(data) {
		doc, err := fromOpenShell(data)
		if err != nil {
			return Document{}, err
		}
		return doc, nil
	}
	var d Document
	if err := yaml.Unmarshal(data, &d); err != nil {
		return Document{}, fmt.Errorf("policy: parse: %w", err)
	}
	return d, nil
}

func looksOpenShell(data []byte) bool {
	var probe struct {
		FilesystemPolicy yaml.Node `yaml:"filesystem_policy"`
		NetworkPolicies  yaml.Node `yaml:"network_policies"`
		Landlock         yaml.Node `yaml:"landlock"`
		Filesystem       yaml.Node `yaml:"filesystem"`
		Network          yaml.Node `yaml:"network"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return false
	}
	hasOurs := probe.Filesystem.Kind != 0 || probe.Network.Kind != 0
	if hasOurs {
		return false
	}
	return probe.FilesystemPolicy.Kind != 0 ||
		probe.NetworkPolicies.Kind != 0 ||
		probe.Landlock.Kind != 0
}

// Validate performs fail-closed structural checks.
func (d Document) Validate() error {
	if d.Version != 1 {
		return fmt.Errorf("policy: version must be 1 (got %d)", d.Version)
	}
	if d.Filesystem != nil {
		mode := strings.ToLower(strings.TrimSpace(d.Filesystem.Mode))
		if mode == "" {
			mode = "best_effort"
		}
		switch mode {
		case "best_effort", "required":
		default:
			return fmt.Errorf("policy: filesystem.mode must be best_effort|required")
		}
		paths := append(append([]string{}, d.Filesystem.Read...), d.Filesystem.Write...)
		if len(paths) > 256 {
			return fmt.Errorf("policy: too many filesystem paths (%d)", len(paths))
		}
		for _, p := range paths {
			if err := validateFSPath(p); err != nil {
				return err
			}
		}
		for _, p := range d.Filesystem.Write {
			if p == "/" {
				return fmt.Errorf("policy: filesystem.write must not include '/'")
			}
		}
	}
	if d.Process != nil {
		if err := validateProcessIdentity("user", d.Process.User); err != nil {
			return err
		}
		if err := validateProcessIdentity("group", d.Process.Group); err != nil {
			return err
		}
	}
	if d.Network != nil {
		def := strings.ToLower(strings.TrimSpace(d.Network.Default))
		if def == "" {
			def = "deny"
		}
		if def != "deny" {
			return fmt.Errorf("policy: network.default must be deny (got %q)", d.Network.Default)
		}
		for i, rule := range d.Network.Allow {
			if strings.TrimSpace(rule.Host) == "" {
				return fmt.Errorf("policy: network.allow[%d]: host required", i)
			}
			ports := rule.EffectivePorts()
			if len(ports) == 0 {
				return fmt.Errorf("policy: network.allow[%d]: port or ports required", i)
			}
			for _, p := range ports {
				if p < 1 || p > 65535 {
					return fmt.Errorf("policy: network.allow[%d]: invalid port %d", i, p)
				}
			}
			if isTLDWildcard(rule.Host) {
				return fmt.Errorf("policy: network.allow[%d]: TLD wildcard host %q rejected", i, rule.Host)
			}
		}
	}
	if d.Display != nil {
		mode := strings.ToLower(strings.TrimSpace(d.Display.Mode))
		if mode == "" {
			mode = "none"
		}
		switch mode {
		case "none", "novnc":
		default:
			return fmt.Errorf("policy: display.mode must be none|novnc")
		}
	}
	return nil
}

// EffectivePorts returns ports, falling back to single Port.
func (r AllowRule) EffectivePorts() []int {
	if len(r.Ports) > 0 {
		return r.Ports
	}
	if r.Port != 0 {
		return []int{r.Port}
	}
	return nil
}

// HardenMode returns best_effort when unset.
func (d Document) HardenMode() string {
	if d.Filesystem == nil {
		return "best_effort"
	}
	c := strings.ToLower(strings.TrimSpace(d.Filesystem.Mode))
	if c == "" {
		return "best_effort"
	}
	if c == "required" {
		return "required"
	}
	return "best_effort"
}

// AllowRules returns the egress allow list (nil-safe).
func (d Document) AllowRules() []AllowRule {
	if d.Network == nil {
		return nil
	}
	return d.Network.Allow
}

func validateFSPath(p string) error {
	if p == "" {
		return fmt.Errorf("policy: empty filesystem path")
	}
	if len(p) > 4096 {
		return fmt.Errorf("policy: filesystem path too long (%d)", len(p))
	}
	if !path.IsAbs(p) {
		return fmt.Errorf("policy: filesystem path must be absolute: %q", p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("policy: filesystem path must not contain '..': %q", p)
	}
	return nil
}

func validateProcessIdentity(field, value string) error {
	if value == "" {
		return nil
	}
	if value == "0" || value == "root" {
		return fmt.Errorf("policy: process.%s must not be root", field)
	}
	if value == "4294967295" {
		return fmt.Errorf("policy: process.%s invalid identity sentinel", field)
	}
	return nil
}

func isTLDWildcard(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "*" || h == "**" {
		return true
	}
	if strings.HasPrefix(h, "*.") && !strings.Contains(h[2:], ".") {
		return true
	}
	if strings.HasPrefix(h, "**.") && !strings.Contains(h[3:], ".") {
		return true
	}
	return false
}
