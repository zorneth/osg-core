// Package policy defines the canonical sandbox policy YAML schema and validation.
package policy

import (
	"fmt"
	"net"
	"os"
	"path"
	"strings"

	"github.com/zorneth/osg-core/defaults"
	"gopkg.in/yaml.v3"
)

// Document is the canonical osg sandbox policy (product schema).
type Document struct {
	Version     int          `yaml:"version" json:"version"`
	Filesystem  *Filesystem  `yaml:"filesystem,omitempty" json:"filesystem,omitempty"`
	Process     *Process     `yaml:"process,omitempty" json:"process,omitempty"`
	Network     *Network     `yaml:"network,omitempty" json:"network,omitempty"`
	Inference   *Inference   `yaml:"inference,omitempty" json:"inference,omitempty"`
	Display     *Display     `yaml:"display,omitempty" json:"display,omitempty"`
	Credentials *Credentials `yaml:"credentials,omitempty" json:"credentials,omitempty"`
	// Binaries is a top-level TOFU path allowlist (globs). Empty = no global binary gate.
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`
	// RegoPath is an optional Rego policy file evaluated after Go L4/L7 allow.
	RegoPath string `yaml:"rego_path,omitempty" json:"rego_path,omitempty"`
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

// AllowRule is one egress allow entry (L4 + optional L7).
type AllowRule struct {
	ID       string   `yaml:"id,omitempty" json:"id,omitempty"`
	Host     string   `yaml:"host,omitempty" json:"host,omitempty"`
	Port     int      `yaml:"port,omitempty" json:"port,omitempty"`
	Ports    []int    `yaml:"ports,omitempty" json:"ports,omitempty"`
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`

	// L7 (P9). Empty Protocol = L4 CONNECT tunnel only.
	Protocol   string       `yaml:"protocol,omitempty" json:"protocol,omitempty"`     // rest | websocket | graphql | mcp
	TLS        string       `yaml:"tls,omitempty" json:"tls,omitempty"`               // terminate | passthrough
	Access     string       `yaml:"access,omitempty" json:"access,omitempty"`         // read-only | read-write | full
	Path       string       `yaml:"path,omitempty" json:"path,omitempty"`             // endpoint path scope / glob
	Rules      []L7Rule     `yaml:"rules,omitempty" json:"rules,omitempty"`
	DenyRules  []L7DenyRule `yaml:"deny_rules,omitempty" json:"deny_rules,omitempty"`
	AllowedIPs []string     `yaml:"allowed_ips,omitempty" json:"allowed_ips,omitempty"` // CIDR/IP; private IPs need this
	// Enforcement is enforce (default) or audit (log L7 violations but allow).
	Enforcement string `yaml:"enforcement,omitempty" json:"enforcement,omitempty"`
	// CredentialKeys is set by provider composition (not user YAML); binds rewrite scope.
	CredentialKeys []string `yaml:"-" json:"-"`
	// WebsocketCredentialRewrite enables placeholder rewrite on client WS text frames.
	WebsocketCredentialRewrite bool `yaml:"websocket_credential_rewrite,omitempty" json:"websocket_credential_rewrite,omitempty"`
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

// Load reads and parses a policy YAML file (ours or legacy-shaped).
func Load(path string) (Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	return Parse(b)
}

// Parse unmarshals policy YAML. legacy-shaped keys are imported automatically.
func Parse(data []byte) (Document, error) {
	if looksLegacy(data) {
		doc, err := fromLegacy(data)
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

func looksLegacy(data []byte) bool {
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
			if err := validateAllowRule(fmt.Sprintf("network.allow[%d]", i), rule); err != nil {
				return err
			}
		}
	}
	if d.Inference != nil {
		if _, err := ExpandInferenceRules(d.Inference); err != nil {
			return err
		}
		for i, rule := range d.Inference.Allow {
			if err := validateAllowRule(fmt.Sprintf("inference.allow[%d]", i), rule); err != nil {
				return err
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
	for i, b := range d.Binaries {
		b = strings.TrimSpace(b)
		if b == "" {
			return fmt.Errorf("policy: binaries[%d]: empty", i)
		}
		if strings.Contains(b, "..") {
			return fmt.Errorf("policy: binaries[%d]: must not contain '..'", i)
		}
	}
	if p := strings.TrimSpace(d.RegoPath); p != "" && strings.Contains(p, "\x00") {
		return fmt.Errorf("policy: rego_path invalid")
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

// AllowRules returns network.allow plus expanded inference rules (nil-safe).
func (d Document) AllowRules() []AllowRule {
	var out []AllowRule
	if d.Network != nil {
		out = append(out, d.Network.Allow...)
	}
	inf, err := ExpandInferenceRules(d.Inference)
	if err == nil {
		out = append(out, inf...)
	}
	return out
}

// Enforcement modes.
const (
	EnforcementEnforce = "enforce"
	EnforcementAudit   = "audit"
)

// IsAudit reports whether L7 violations should be logged and allowed.
func (r AllowRule) IsAudit() bool {
	return strings.EqualFold(strings.TrimSpace(r.Enforcement), EnforcementAudit)
}

// ValidateAllowRule validates one network allow entry (exported for provider profiles).
func ValidateAllowRule(prefix string, rule AllowRule) error {
	return validateAllowRule(prefix, rule)
}

func validateAllowRule(prefix string, rule AllowRule) error {
	if strings.TrimSpace(rule.Host) == "" && len(rule.AllowedIPs) == 0 {
		return fmt.Errorf("policy: %s: host or allowed_ips required", prefix)
	}
	ports := rule.EffectivePorts()
	if len(ports) == 0 {
		return fmt.Errorf("policy: %s: port or ports required", prefix)
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("policy: %s: invalid port %d", prefix, p)
		}
	}
	if rule.Host != "" && isTLDWildcard(rule.Host) {
		return fmt.Errorf("policy: %s: TLD wildcard host %q rejected", prefix, rule.Host)
	}
	enf := strings.ToLower(strings.TrimSpace(rule.Enforcement))
	switch enf {
	case "", EnforcementEnforce, EnforcementAudit:
	default:
		return fmt.Errorf("policy: %s: enforcement must be enforce|audit (got %q)", prefix, rule.Enforcement)
	}
	for j, cidr := range rule.AllowedIPs {
		if err := validateCIDROrIP(fmt.Sprintf("%s.allowed_ips[%d]", prefix, j), cidr); err != nil {
			return err
		}
	}
	return validateL7(prefix, rule)
}

func validateL7(prefix string, rule AllowRule) error {
	proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
	tlsMode := strings.ToLower(strings.TrimSpace(rule.TLS))
	access := strings.ToLower(strings.TrimSpace(rule.Access))

	switch proto {
	case "", ProtocolREST, ProtocolWebsocket, ProtocolGraphQL, ProtocolMCP:
	default:
		return fmt.Errorf("policy: %s: protocol must be rest|websocket|graphql|mcp (got %q)", prefix, rule.Protocol)
	}
	switch tlsMode {
	case "", TLSTerminate, TLSPassthrough:
	default:
		return fmt.Errorf("policy: %s: tls must be terminate|passthrough (got %q)", prefix, rule.TLS)
	}
	if tlsMode == TLSTerminate && proto == "" {
		return fmt.Errorf("policy: %s: tls: terminate requires protocol", prefix)
	}
	switch access {
	case "", AccessReadOnly, AccessReadWrite, AccessFull:
	default:
		return fmt.Errorf("policy: %s: access must be read-only|read-write|full (got %q)", prefix, rule.Access)
	}
	if access != "" && len(rule.Rules) > 0 {
		return fmt.Errorf("policy: %s: access and rules are mutually exclusive", prefix)
	}
	if rule.NeedsL7() {
		switch proto {
		case ProtocolREST, ProtocolWebsocket, ProtocolGraphQL, ProtocolMCP:
			// ok
		case "":
			return fmt.Errorf("policy: %s: L7 fields require protocol", prefix)
		default:
			return fmt.Errorf("policy: %s: protocol %q unsupported", prefix, proto)
		}
		if access == "" && len(rule.Rules) == 0 && len(rule.DenyRules) == 0 {
			return fmt.Errorf("policy: %s: protocol %q requires access or rules", prefix, proto)
		}
		if access != "" {
			if rule.ExpandedL7Allows() == nil {
				return fmt.Errorf("policy: %s: invalid access %q", prefix, rule.Access)
			}
		}
		for i, r := range rule.Rules {
			if r.Allow == nil {
				return fmt.Errorf("policy: %s.rules[%d]: allow required", prefix, i)
			}
		}
		// HTTPS + L7 needs terminate so the proxy can inspect.
		for _, p := range rule.EffectivePorts() {
			if p == defaults.HTTPSPort && tlsMode != TLSTerminate {
				return fmt.Errorf("policy: %s: port %d with L7 requires tls: terminate", prefix, defaults.HTTPSPort)
			}
		}
		if tlsMode == TLSPassthrough {
			return fmt.Errorf("policy: %s: tls: passthrough cannot inspect L7", prefix)
		}
	}
	return nil
}

func validateCIDROrIP(prefix, s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("policy: %s: empty", prefix)
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return nil
	}
	return fmt.Errorf("policy: %s: invalid IP/CIDR %q", prefix, s)
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
