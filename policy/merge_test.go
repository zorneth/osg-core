package policy_test

import (
	"testing"

	"github.com/zorneth/osg-core/policy"
)

func TestMergeGlobalPrependsAllows(t *testing.T) {
	sandbox := policy.Document{Version: 1}
	sandbox.SetNetworkAllows([]policy.AllowRule{{Host: "sandbox.example", Port: 443}})
	global := policy.Document{Version: 1, Binaries: []string{"/usr/bin/curl"}}
	global.SetNetworkAllows([]policy.AllowRule{{Host: "global.example", Port: 443}})
	out, err := policy.MergeGlobal(sandbox, global)
	if err != nil {
		t.Fatal(err)
	}
	allows := out.NetworkAllows()
	if len(allows) != 2 || allows[0].Host != "global.example" {
		t.Fatalf("allow=%v", allows)
	}
	if len(out.Binaries) != 1 {
		t.Fatalf("binaries=%v", out.Binaries)
	}
}

func TestGraphQLPolicy(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		Host: "gql.example", Port: 443, Protocol: "graphql", TLS: "terminate", Access: "read-write",
	}})
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	allows := doc.NetworkAllows()[0].ExpandedL7Allows()
	if len(allows) != 2 {
		t.Fatalf("allows=%v", allows)
	}
}
