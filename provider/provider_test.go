package provider

import (
	"testing"

	"github.com/zorneth/osg-core/policy"
)

func TestCompose(t *testing.T) {
	base := policy.Document{
		Version: 1,
		Network: &policy.Network{Default: "deny"},
	}
	p := Profile{
		ID: "nvidia",
		Endpoints: []policy.AllowRule{{
			Host: "integrate.api.nvidia.com", Port: 443,
			Protocol: "rest", TLS: "terminate", Access: "read-write",
		}},
		Binaries: []string{"/usr/bin/curl"},
		Credentials: []Credential{{
			Name: "api_key", EnvVars: []string{"NVIDIA_API_KEY"},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	out := Compose(base, []Layer{{InstanceName: "nv", Profile: p}}, false)
	if len(out.Network.Allow) != 1 {
		t.Fatalf("allow=%d", len(out.Network.Allow))
	}
	if out.Network.Allow[0].ID != "provider.nv.0" {
		t.Fatalf("id=%s", out.Network.Allow[0].ID)
	}
	if len(out.Network.Allow[0].Binaries) != 1 {
		t.Fatalf("binaries=%v", out.Network.Allow[0].Binaries)
	}
	if out.Credentials == nil || len(out.Credentials.EnvAllow) != 1 || out.Credentials.EnvAllow[0] != "NVIDIA_API_KEY" {
		t.Fatalf("env=%v", out.Credentials)
	}
	if len(base.Network.Allow) != 0 {
		t.Fatalf("base mutated: %d", len(base.Network.Allow))
	}
	fresh := policy.Document{Version: 1, Network: &policy.Network{Default: "deny"}}
	suppressed := Compose(fresh, []Layer{{InstanceName: "nv", Profile: p}}, true)
	if len(suppressed.Network.Allow) != 0 {
		t.Fatalf("expected suppress, got %d", len(suppressed.Network.Allow))
	}
}

func TestAuditMatchHTTP(t *testing.T) {
	rule := policy.AllowRule{
		Host: "api.example.com", Port: 443, Protocol: "rest", TLS: "terminate",
		Access: "read-only", Enforcement: "audit",
	}
	ok, _ := rule.MatchHTTP("POST", "/v1")
	if ok {
		t.Fatal("POST should fail MatchHTTP on read-only")
	}
	if !rule.IsAudit() {
		t.Fatal("expected audit")
	}
}
