package policy

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// OpenShell-shaped wire format (compat import only).
type openShellDoc struct {
	Version            int                        `yaml:"version"`
	FilesystemPolicy   *openShellFS               `yaml:"filesystem_policy"`
	Landlock           *openShellLandlock         `yaml:"landlock"`
	Process            *openShellProcess          `yaml:"process"`
	NetworkPolicies    map[string]openShellNetRule `yaml:"network_policies"`
	OSG                *openShellOSG              `yaml:"osg"`
}

type openShellFS struct {
	IncludeWorkdir bool     `yaml:"include_workdir"`
	ReadOnly       []string `yaml:"read_only"`
	ReadWrite      []string `yaml:"read_write"`
}

type openShellLandlock struct {
	Compatibility string `yaml:"compatibility"`
}

type openShellProcess struct {
	RunAsUser  string `yaml:"run_as_user"`
	RunAsGroup string `yaml:"run_as_group"`
}

type openShellNetRule struct {
	Name      string              `yaml:"name"`
	Endpoints []openShellEndpoint `yaml:"endpoints"`
	Binaries  []openShellBinary   `yaml:"binaries"`
}

type openShellEndpoint struct {
	Host  string `yaml:"host"`
	Port  int    `yaml:"port"`
	Ports []int  `yaml:"ports"`
}

type openShellBinary struct {
	Path string `yaml:"path"`
}

type openShellOSG struct {
	Display     *Display     `yaml:"display"`
	Credentials *Credentials `yaml:"credentials"`
}

func fromOpenShell(data []byte) (Document, error) {
	var raw openShellDoc
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Document{}, fmt.Errorf("policy: openshell import: %w", err)
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
			net.Allow = append(net.Allow, AllowRule{
				ID:       id,
				Host:     ep.Host,
				Port:     ep.Port,
				Ports:    append([]int{}, ep.Ports...),
				Binaries: append([]string{}, bins...),
			})
		}
	}
	doc.Network = net
	if raw.OSG != nil {
		doc.Display = raw.OSG.Display
		doc.Credentials = raw.OSG.Credentials
	}
	return doc, nil
}
