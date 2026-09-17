package policy_test

import (
	"testing"

	"github.com/zorneth/osg-core/policy"
)

func TestParseEndpointSpec(t *testing.T) {
	ep, err := policy.ParseEndpointSpec("api.github.com:443:read-only:rest:enforce")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "api.github.com" || ep.Port != 443 || ep.Access != "read-only" || ep.Protocol != "rest" || ep.Enforcement != "enforce" {
		t.Fatalf("%+v", ep)
	}
	if _, err := policy.ParseEndpointSpec("bad"); err == nil {
		t.Fatal("expected error")
	}
}

func TestApplyNetworkUpdateMerge(t *testing.T) {
	base := policy.Document{Version: 1}
	base.SetNetworkAllows([]policy.AllowRule{
		{Host: "api.github.com", Port: 443, Protocol: "rest"},
	})
	out, err := policy.ApplyNetworkUpdate(base, policy.NetworkUpdate{
		AddEndpoints: []policy.EndpointSpec{{Host: "api.github.com", Port: 443, Protocol: "rest"}},
		AddAllows:    []policy.MethodPathSpec{{Host: "api.github.com", Port: 443, Method: "POST", Path: "/repos/*/issues"}},
		Binaries:     []string{"/usr/bin/gh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	allows := out.NetworkAllows()
	if len(allows) != 1 {
		t.Fatalf("rules=%d", len(allows))
	}
	r := allows[0]
	if len(r.Rules) != 1 || r.Rules[0].Allow == nil || r.Rules[0].Allow.Method != "POST" {
		t.Fatalf("rules=%+v", r.Rules)
	}
	if len(r.Binaries) != 1 || r.Binaries[0] != "/usr/bin/gh" {
		t.Fatalf("binaries=%v", r.Binaries)
	}
}

func TestApplyNetworkUpdateAddHost(t *testing.T) {
	base := policy.Document{Version: 1}
	out, err := policy.ApplyNetworkUpdate(base, policy.NetworkUpdate{
		AddEndpoints: []policy.EndpointSpec{{Host: "example.com", Port: 443}},
	})
	if err != nil {
		t.Fatal(err)
	}
	allows := out.NetworkAllows()
	if len(allows) != 1 || allows[0].Host != "example.com" {
		t.Fatalf("%+v", allows)
	}
}
