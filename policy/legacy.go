package policy

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// legacy-shaped wire format (compat import only).
type legacyDoc struct {
	Version          int                        `yaml:"version"`
	FilesystemPolicy *legacyFS                  `yaml:"filesystem_policy"`
	Landlock         *legacyLandlock            `yaml:"landlock"`
	Process          *legacyProcess             `yaml:"process"`
	NetworkPolicies  map[string]legacyNetRule   `yaml:"network_policies"`
	OSG              *legacyOSG                 `yaml:"osg"`
}

type legacyFS struct {
	IncludeWorkdir bool     `yaml:"include_workdir"`
	ReadOnly       []string `yaml:"read_only"`
	ReadWrite      []string `yaml:"read_write"`
}

type legacyLandlock struct {
	Compatibility string `yaml:"compatibility"`
}

type legacyProcess struct {
	RunAsUser  string `yaml:"run_as_user"`
	RunAsGroup string `yaml:"run_as_group"`
}

type legacyNetRule struct {
	Name      string           `yaml:"name"`
	Endpoints []legacyEndpoint `yaml:"endpoints"`
	Binaries  []legacyBinary   `yaml:"binaries"`
}

type legacyEndpoint struct {
	Host       string             `yaml:"host"`
	Path       string             `yaml:"path"`
	Port       int                `yaml:"port"`
	Ports      []int              `yaml:"ports"`
	Protocol   string             `yaml:"protocol"`
	TLS        string             `yaml:"tls"`
	Access     string             `yaml:"access"`
	AllowedIPs []string           `yaml:"allowed_ips"`
	Rules      []legacyL7Rule     `yaml:"rules"`
	DenyRules  []legacyL7DenyRule `yaml:"deny_rules"`
}

type legacyL7Rule struct {
	Allow *L7Allow `yaml:"allow"`
}

type legacyL7DenyRule struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

type legacyBinary struct {
	Path string `yaml:"path"`
}

type legacyOSG struct {
	Display     *Display     `yaml:"display"`
	Credentials *Credentials `yaml:"credentials"`
}

func fromLegacy(data []byte) (Document, error) {
	var raw legacyDoc
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Document{}, fmt.Errorf("policy: legacy import: %w", err)
	}
	doc := Document{Version: raw.Version}
	if raw.FilesystemPolicy != nil || raw.Landlock != nil {
		fs := &Filesystem{}
		if raw.FilesystemPolicy != nil {
			fs.IncludeWorkdir = raw.FilesystemPolicy.IncludeWorkdir
			fs.Read = append([]string{}, raw.FilesystemPolicy.ReadOnly...)
			fs.Write = append([]string{}, raw.FilesystemPolicy.ReadWrite...)
		}
		if raw.Landlock != nil {
			c := strings.ToLower(strings.TrimSpace(raw.Landlock.Compatibility))
			switch c {
			case "hard_requirement":
				fs.Mode = "required"
			default:
				fs.Mode = "best_effort"
			}
		}
		doc.Filesystem = fs
	}
	if raw.Process != nil {
		doc.Process = &Process{
			User:  raw.Process.RunAsUser,
			Group: raw.Process.RunAsGroup,
		}
	}
	net := &Network{Default: "deny"}
	for key, rule := range raw.NetworkPolicies {
		id := rule.Name
		if id == "" {
			id = key
		}
		var bins []string
		for _, b := range rule.Binaries {
			if b.Path != "" {
				bins = append(bins, b.Path)
			}
		}
		for _, ep := range rule.Endpoints {
			ar := AllowRule{
				ID:         id,
				Host:       ep.Host,
				Port:       ep.Port,
				Ports:      append([]int{}, ep.Ports...),
				Binaries:   append([]string{}, bins...),
				Protocol:   ep.Protocol,
				TLS:        ep.TLS,
				Access:     ep.Access,
				Path:       ep.Path,
				AllowedIPs: append([]string{}, ep.AllowedIPs...),
			}
			for _, r := range ep.Rules {
				if r.Allow == nil {
					continue
				}
				a := *r.Allow
				ar.Rules = append(ar.Rules, L7Rule{Allow: &a})
			}
			for _, d := range ep.DenyRules {
				ar.DenyRules = append(ar.DenyRules, L7DenyRule{Method: d.Method, Path: d.Path})
			}
			net.Allow = append(net.Allow, ar)
		}
	}
	doc.Network = net
	if raw.OSG != nil {
		doc.Display = raw.OSG.Display
		doc.Credentials = raw.OSG.Credentials
	}
	return doc, nil
}
