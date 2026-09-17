package policy_test

import (
	"testing"

	"github.com/zorneth/osg-core/policy"
)

func docWithAllows(rules ...policy.AllowRule) policy.Document {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows(rules)
	return doc
}

func TestL7ValidateREST(t *testing.T) {
	doc := docWithAllows(policy.AllowRule{
		ID: "api", Host: "api.example.com", Port: 80, Protocol: "rest", Access: "read-only",
	})
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestL7ValidateHTTPSRequiresTerminate(t *testing.T) {
	doc := docWithAllows(policy.AllowRule{
		Host: "api.example.com", Port: 443, Protocol: "rest", Access: "read-only",
	})
	if err := doc.Validate(); err == nil {
		t.Fatal("expected error for 443 without tls terminate")
	}
}

func TestL7MatchHTTP(t *testing.T) {
	rule := policy.AllowRule{
		Host: "api.example.com", Port: 80, Protocol: "rest", Access: "read-only",
	}
	ok, _ := rule.MatchHTTP("GET", "/v1/x")
	if !ok {
		t.Fatal("GET should allow")
	}
	ok, _ = rule.MatchHTTP("POST", "/v1/x")
	if ok {
		t.Fatal("POST should deny on read-only")
	}
}

func TestWebsocketPolicyValidate(t *testing.T) {
	doc := docWithAllows(policy.AllowRule{
		Host: "realtime.example.com", Port: 443, Protocol: "websocket", TLS: "terminate", Access: "read-write",
	})
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	allows := doc.NetworkAllows()[0].ExpandedL7Allows()
	if len(allows) != 2 {
		t.Fatalf("allows=%v", allows)
	}
}

func TestL7ExplicitRulesAndDeny(t *testing.T) {
	rule := policy.AllowRule{
		Host: "api.example.com", Port: 80, Protocol: "rest",
		Rules: []policy.L7Rule{
			{Allow: &policy.L7Allow{Method: "POST", Path: "/v1/chat"}},
			{Allow: &policy.L7Allow{Method: "GET", Path: "/v1/**"}},
		},
		DenyRules: []policy.L7DenyRule{
			{Method: "GET", Path: "/v1/admin/**"},
		},
	}
	doc := docWithAllows(rule)
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}
