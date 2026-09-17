// Package policy defines the OpenShell-shaped sandbox policy YAML schema.
package policy

import (
	"fmt"
	"net"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/zorneth/osg-core/defaults"
	"gopkg.in/yaml.v3"
)

// Document is the canonical sandbox policy (OpenShell YAML naming).
type Document struct {
	Version            int                       `yaml:"version" json:"version"`
	FilesystemPolicy   *FilesystemPolicy         `yaml:"filesystem_policy,omitempty" json:"filesystem_policy,omitempty"`
	Landlock           *Landlock                 `yaml:"landlock,omitempty" json:"landlock,omitempty"`
	Process            *Process                  `yaml:"process,omitempty" json:"process,omitempty"`
	NetworkPolicies    map[string]NetworkPolicy  `yaml:"network_policies,omitempty" json:"network_policies,omitempty"`
	NetworkMiddlewares map[string]yaml.Node      `yaml:"network_middlewares,omitempty" json:"network_middlewares,omitempty"`
	Inference          *Inference                `yaml:"inference,omitempty" json:"inference,omitempty"`
	Display            *Display                  `yaml:"display,omitempty" json:"display,omitempty"`
	Credentials        *Credentials              `yaml:"credentials,omitempty" json:"credentials,omitempty"`
	// Binaries is a top-level TOFU path allowlist (globs). Empty = no global binary gate.
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`
	// RegoPath is an optional Rego policy file evaluated after Go L4/L7 allow.
	RegoPath string `yaml:"rego_path,omitempty" json:"rego_path,omitempty"`
}

// FilesystemPolicy is Landlock path policy + workdir include flag.
type FilesystemPolicy struct {
	IncludeWorkdir bool     `yaml:"include_workdir" json:"include_workdir"`
	ReadOnly       []string `yaml:"read_only,omitempty" json:"read_only,omitempty"`
	ReadWrite      []string `yaml:"read_write,omitempty" json:"read_write,omitempty"`
}

// Landlock configures Landlock compatibility mode.
type Landlock struct {
	// Compatibility: best_effort | hard_requirement.
	Compatibility string `yaml:"compatibility,omitempty" json:"compatibility,omitempty"`
}

// Process is sandbox process identity (omit to let the compute driver choose).
type Process struct {
	RunAsUser  string `yaml:"run_as_user,omitempty" json:"run_as_user,omitempty"`
	RunAsGroup string `yaml:"run_as_group,omitempty" json:"run_as_group,omitempty"`
}

// NetworkPolicy is one named egress policy (map value under network_policies).
type NetworkPolicy struct {
	Name      string          `yaml:"name,omitempty" json:"name,omitempty"`
	Endpoints []AllowRule     `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	Binaries  []NetworkBinary `yaml:"binaries,omitempty" json:"binaries,omitempty"`
}

// NetworkBinary restricts which binaries may use the rule (empty = any).
type NetworkBinary struct {
	Path string `yaml:"path" json:"path"`
}

// AllowRule is one egress endpoint (L4 + optional L7). Used under
// network_policies.*.endpoints and as the flattened engine view.
type AllowRule struct {
	ID       string   `yaml:"id,omitempty" json:"id,omitempty"`
	Host     string   `yaml:"host,omitempty" json:"host,omitempty"`
	Port     int      `yaml:"port,omitempty" json:"port,omitempty"`
	Ports    []int    `yaml:"ports,omitempty" json:"ports,omitempty"`
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`

	// L7. Empty Protocol = L4 CONNECT tunnel only.
	Protocol   string       `yaml:"protocol,omitempty" json:"protocol,omitempty"` // rest | websocket | graphql | mcp
	TLS        string       `yaml:"tls,omitempty" json:"tls,omitempty"`           // terminate | passthrough | clear
	Access     string       `yaml:"access,omitempty" json:"access,omitempty"`     // read-only | read-write | full
	Path       string       `yaml:"path,omitempty" json:"path,omitempty"`
	Rules      []L7Rule     `yaml:"rules,omitempty" json:"rules,omitempty"`
	DenyRules  []L7DenyRule `yaml:"deny_rules,omitempty" json:"deny_rules,omitempty"`
	AllowedIPs []string     `yaml:"allowed_ips,omitempty" json:"allowed_ips,omitempty"`
	// Enforcement is enforce (default) or audit.
	Enforcement string `yaml:"enforcement,omitempty" json:"enforcement,omitempty"`
	// CredentialKeys binds osg:resolve:env:KEY rewrite to this endpoint.
	CredentialKeys []string `yaml:"credential_keys,omitempty" json:"credential_keys,omitempty"`
	WebsocketCredentialRewrite   bool `yaml:"websocket_credential_rewrite,omitempty" json:"websocket_credential_rewrite,omitempty"`
	RequestBodyCredentialRewrite bool `yaml:"request_body_credential_rewrite,omitempty" json:"request_body_credential_rewrite,omitempty"`
	AllowEncodedSlash            bool `yaml:"allow_encoded_slash,omitempty" json:"allow_encoded_slash,omitempty"`
	AllowUninspectedCredentials  bool `yaml:"allow_uninspected_credentials,omitempty" json:"allow_uninspected_credentials,omitempty"`
}

// Display is the noVNC surface (osg product extension).
type Display struct {
	Mode    string `yaml:"mode,omitempty" json:"mode,omitempty"` // none | novnc
	Publish string `yaml:"publish,omitempty" json:"publish,omitempty"`
	Port    int    `yaml:"port,omitempty" json:"port,omitempty"`
	Auth    string `yaml:"auth,omitempty" json:"auth,omitempty"`
	Browser string `yaml:"browser,omitempty" json:"browser,omitempty"`
}

// Credentials controls host-side env injection (osg product extension).
type Credentials struct {
	EnvAllow    []string `yaml:"env_allow,omitempty" json:"env_allow,omitempty"`
	WriteToDisk bool     `yaml:"write_to_disk,omitempty" json:"write_to_disk,omitempty"`
}

// Load reads and parses a policy YAML file.
func Load(path string) (Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	return Parse(b)
}

// Parse unmarshals OpenShell-shaped policy YAML.
func Parse(data []byte) (Document, error) {
	if err := rejectRemovedSchema(data); err != nil {
		return Document{}, err
	}
	var d Document
	if err := yaml.Unmarshal(data, &d); err != nil {
		return Document{}, fmt.Errorf("policy: parse: %w", err)
	}
	return d, nil
}

// rejectRemovedSchema fails closed on the removed keys (filesystem / network).
func rejectRemovedSchema(data []byte) error {
	var probe struct {
		Filesystem yaml.Node `yaml:"filesystem"`
		Network    yaml.Node `yaml:"network"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil
	}
	if probe.Filesystem.Kind != 0 {
		return fmt.Errorf("policy: key \"filesystem\" removed; use OpenShell naming filesystem_policy / landlock")
	}
	if probe.Network.Kind != 0 {
		return fmt.Errorf("policy: key \"network\" removed; use OpenShell naming network_policies")
	}
	return nil
}

// Validate performs fail-closed structural checks.
func (d Document) Validate() error {
	if d.Version != 1 {
		return fmt.Errorf("policy: version must be 1 (got %d)", d.Version)
	}
	if d.Landlock != nil {
		c := strings.ToLower(strings.TrimSpace(d.Landlock.Compatibility))
		if c == "" {
			c = "best_effort"
		}
		switch c {
		case "best_effort", "hard_requirement":
		default:
			return fmt.Errorf("policy: landlock.compatibility must be best_effort|hard_requirement")
		}
	}
	if d.FilesystemPolicy != nil {
		paths := append(append([]string{}, d.FilesystemPolicy.ReadOnly...), d.FilesystemPolicy.ReadWrite...)
		if len(paths) > 256 {
			return fmt.Errorf("policy: too many filesystem paths (%d)", len(paths))
		}
		for _, p := range paths {
			if err := validateFSPath(p); err != nil {
				return err
			}
		}
		for _, p := range d.FilesystemPolicy.ReadWrite {
			if p == "/" {
				return fmt.Errorf("policy: filesystem_policy.read_write must not include '/'")
			}
		}
	}
	if d.Process != nil {
		if err := validateProcessIdentity("run_as_user", d.Process.RunAsUser); err != nil {
			return err
		}
		if err := validateProcessIdentity("run_as_group", d.Process.RunAsGroup); err != nil {
			return err
		}
	}
	for key, rule := range d.NetworkPolicies {
		name := rule.Name
		if name == "" {
			name = key
		}
		bins := binaryPaths(rule.Binaries)
		for j, ep := range rule.Endpoints {
			r := ep
			if r.ID == "" {
				r.ID = name
			}
			if len(r.Binaries) == 0 && len(bins) > 0 {
				r.Binaries = bins
			}
			prefix := fmt.Sprintf("network_policies[%q].endpoints[%d]", key, j)
			if err := validateAllowRule(prefix, r); err != nil {
				return err
			}
		}
		for j, bin := range rule.Binaries {
			if strings.TrimSpace(bin.Path) == "" {
				return fmt.Errorf("policy: network_policies[%q].binaries[%d]: path required", key, j)
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

func binaryPaths(bins []NetworkBinary) []string {
	var out []string
	for _, b := range bins {
		if p := strings.TrimSpace(b.Path); p != "" {
			out = append(out, p)
		}
	}
	return out
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

// HardenMode returns best_effort|required from landlock.compatibility.
func (d Document) HardenMode() string {
	if d.Landlock == nil {
		return "best_effort"
	}
	c := strings.ToLower(strings.TrimSpace(d.Landlock.Compatibility))
	if c == "hard_requirement" {
		return "required"
	}
	return "best_effort"
}

// FSRead returns filesystem_policy.read_only (nil-safe).
func (d Document) FSRead() []string {
	if d.FilesystemPolicy == nil {
		return nil
	}
	return d.FilesystemPolicy.ReadOnly
}

// FSWrite returns filesystem_policy.read_write (nil-safe).
func (d Document) FSWrite() []string {
	if d.FilesystemPolicy == nil {
		return nil
	}
	return d.FilesystemPolicy.ReadWrite
}

// IncludeWorkdir reports filesystem_policy.include_workdir.
func (d Document) IncludeWorkdir() bool {
	return d.FilesystemPolicy != nil && d.FilesystemPolicy.IncludeWorkdir
}

// ProcessUser returns process.run_as_user.
func (d Document) ProcessUser() string {
	if d.Process == nil {
		return ""
	}
	return d.Process.RunAsUser
}

// ProcessGroup returns process.run_as_group.
func (d Document) ProcessGroup() string {
	if d.Process == nil {
		return ""
	}
	return d.Process.RunAsGroup
}

// NetworkAllows flattens network_policies endpoints (no inference).
func (d Document) NetworkAllows() []AllowRule {
	if len(d.NetworkPolicies) == 0 {
		return nil
	}
	// Stable-ish order: sort keys.
	keys := make([]string, 0, len(d.NetworkPolicies))
	for k := range d.NetworkPolicies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []AllowRule
	for _, key := range keys {
		rule := d.NetworkPolicies[key]
		name := rule.Name
		if name == "" {
			name = key
		}
		bins := binaryPaths(rule.Binaries)
		for _, ep := range rule.Endpoints {
			r := ep
			if r.ID == "" {
				r.ID = name
			}
			if len(r.Binaries) == 0 && len(bins) > 0 {
				r.Binaries = append([]string{}, bins...)
			}
			out = append(out, r)
		}
	}
	return out
}

// AllowRules returns network_policies endpoints plus expanded inference rules.
func (d Document) AllowRules() []AllowRule {
	out := d.NetworkAllows()
	inf, err := ExpandInferenceRules(d.Inference)
	if err == nil {
		out = append(out, inf...)
	}
	return out
}

// SetNetworkAllows replaces network_policies with one entry per allow rule id.
func (d *Document) SetNetworkAllows(rules []AllowRule) {
	if len(rules) == 0 {
		d.NetworkPolicies = nil
		return
	}
	out := make(map[string]NetworkPolicy, len(rules))
	for i, r := range rules {
		key := strings.TrimSpace(r.ID)
		if key == "" {
			key = fmt.Sprintf("rule_%d", i)
		}
		ep := r
		ep.ID = ""
		bins := r.Binaries
		ep.Binaries = nil
		var nb []NetworkBinary
		for _, b := range bins {
			nb = append(nb, NetworkBinary{Path: b})
		}
		if existing, ok := out[key]; ok {
			existing.Endpoints = append(existing.Endpoints, ep)
			if len(existing.Binaries) == 0 {
				existing.Binaries = nb
			}
			out[key] = existing
			continue
		}
		out[key] = NetworkPolicy{
			Name:      key,
			Endpoints: []AllowRule{ep},
			Binaries:  nb,
		}
	}
	d.NetworkPolicies = out
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
	case "", TLSTerminate, TLSPassthrough, "clear":
	default:
		return fmt.Errorf("policy: %s: tls must be terminate|passthrough|clear (got %q)", prefix, rule.TLS)
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
