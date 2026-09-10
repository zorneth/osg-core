package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lkmavi/osg-core/engine"
	"github.com/lkmavi/osg-core/policy"
)

const sampleOurs = `
version: 1
filesystem:
  include_workdir: true
  read: [/usr, /lib]
  write: [/tmp]
  mode: best_effort
network:
  default: deny
  allow:
    - id: anthropic
      host: api.anthropic.com
      port: 443
    - id: openai
      host: "*.openai.com"
      ports: [443]
credentials:
  env_allow: [TERM, LANG]
`

const sampleOpenShell = `
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr]
  read_write: [/tmp]
landlock:
  compatibility: best_effort
network_policies:
  model_apis:
    name: model-apis
    endpoints:
      - host: api.anthropic.com
        port: 443
osg:
  credentials:
    env_allow: [TERM]
`

func TestParseOurs(t *testing.T) {
	doc, err := policy.Parse([]byte(sampleOurs))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	if doc.Filesystem == nil || !doc.Filesystem.IncludeWorkdir {
		t.Fatal("filesystem.include_workdir")
	}
	if doc.HardenMode() != "best_effort" {
		t.Fatalf("mode=%q", doc.HardenMode())
	}
	if len(doc.AllowRules()) != 2 {
		t.Fatalf("allow=%d", len(doc.AllowRules()))
	}
}

func TestImportOpenShell(t *testing.T) {
	doc, err := policy.Parse([]byte(sampleOpenShell))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	if doc.Filesystem == nil || len(doc.Filesystem.Read) != 1 {
		t.Fatalf("fs=%+v", doc.Filesystem)
	}
	if len(doc.AllowRules()) != 1 || doc.AllowRules()[0].Host != "api.anthropic.com" {
		t.Fatalf("allow=%+v", doc.AllowRules())
	}
	if doc.Credentials == nil || len(doc.Credentials.EnvAllow) != 1 {
		t.Fatal("credentials from osg:")
	}
}

func TestEngineAllowDeny(t *testing.T) {
	doc, err := policy.Parse([]byte(sampleOurs))
	if err != nil {
		t.Fatal(err)
	}
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	ok, err := eng.Decide(context.Background(), engine.EgressRequest{Host: "api.anthropic.com", Port: 443})
	if err != nil || !ok.Allow {
		t.Fatalf("allow: %+v %v", ok, err)
	}
	deny, err := eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443})
	if err != nil || deny.Allow {
		t.Fatalf("deny: %+v %v", deny, err)
	}
}

func TestEmptyNetworkDenyAll(t *testing.T) {
	doc, err := policy.Parse([]byte("version: 1\nnetwork:\n  default: deny\n"))
	if err != nil {
		t.Fatal(err)
	}
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	d, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "x.com", Port: 443})
	if d.Allow {
		t.Fatal("expected deny")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(path, []byte(sampleOurs), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}
