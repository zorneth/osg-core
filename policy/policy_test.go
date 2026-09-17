package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zorneth/osg-core/engine"
	"github.com/zorneth/osg-core/policy"
)

const sampleOpenShell = `
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib]
  read_write: [/tmp]
landlock:
  compatibility: best_effort
network_policies:
  anthropic:
    name: anthropic
    endpoints:
      - host: api.anthropic.com
        port: 443
  openai:
    name: openai
    endpoints:
      - host: "*.openai.com"
        ports: [443]
credentials:
  env_allow: [TERM, LANG]
`

func TestParseOpenShellNaming(t *testing.T) {
	doc, err := policy.Parse([]byte(sampleOpenShell))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	if !doc.IncludeWorkdir() {
		t.Fatal("filesystem_policy.include_workdir")
	}
	if doc.HardenMode() != "best_effort" {
		t.Fatalf("mode=%q", doc.HardenMode())
	}
	if len(doc.AllowRules()) != 2 {
		t.Fatalf("allow=%d", len(doc.AllowRules()))
	}
}

func TestRejectRemovedSchema(t *testing.T) {
	_, err := policy.Parse([]byte(`
version: 1
filesystem:
  read: [/usr]
network:
  default: deny
`))
	if err == nil {
		t.Fatal("expected reject of removed filesystem/network keys")
	}
}

func TestEngineAllowDeny(t *testing.T) {
	doc, err := policy.Parse([]byte(sampleOpenShell))
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
	doc, err := policy.Parse([]byte("version: 1\nnetwork_policies: {}\n"))
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
	if err := os.WriteFile(path, []byte(sampleOpenShell), 0o644); err != nil {
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

const sampleInference = `
version: 1
network_policies: {}
inference:
  providers: [anthropic, openai]
  allow:
    - id: custom
      host: llm.example.com
      port: 443
`

func TestInferenceProviders(t *testing.T) {
	doc, err := policy.Parse([]byte(sampleInference))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	rules := doc.AllowRules()
	if len(rules) != 3 {
		t.Fatalf("allow=%d %+v", len(rules), rules)
	}
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"api.anthropic.com", "api.openai.com", "llm.example.com"} {
		d, err := eng.Decide(context.Background(), engine.EgressRequest{Host: host, Port: 443})
		if err != nil || !d.Allow {
			t.Fatalf("%s: %+v %v", host, d, err)
		}
	}
	deny, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "evil.example", Port: 443})
	if deny.Allow {
		t.Fatal("expected deny")
	}
}

func TestInferenceUnknownProvider(t *testing.T) {
	doc, err := policy.Parse([]byte("version: 1\ninference:\n  providers: [nope]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err == nil {
		t.Fatal("expected unknown provider error")
	}
}

func TestCredentialEnvKeysFromProviders(t *testing.T) {
	doc, err := policy.Parse([]byte(`
version: 1
inference:
  providers: [anthropic, openai]
credentials:
  env_allow: [TERM]
`))
	if err != nil {
		t.Fatal(err)
	}
	keys := doc.CredentialEnvKeys()
	want := map[string]bool{"TERM": true, "ANTHROPIC_API_KEY": true, "OPENAI_API_KEY": true}
	for _, k := range keys {
		if !want[k] {
			t.Fatalf("unexpected key %q in %v", k, keys)
		}
		delete(want, k)
	}
	if len(want) != 0 {
		t.Fatalf("missing keys %v", want)
	}
}

func TestLandlockHardRequirement(t *testing.T) {
	doc, err := policy.Parse([]byte(`
version: 1
landlock:
  compatibility: hard_requirement
`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.HardenMode() != "required" {
		t.Fatalf("mode=%q", doc.HardenMode())
	}
}
