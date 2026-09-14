// Package engine evaluates egress decisions against a policy.Document.
package engine

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/zorneth/osg-core/hostpattern"
	"github.com/zorneth/osg-core/policy"
	"github.com/zorneth/osg-core/tofu"
)

// Decision is admit / deny for one request.
type Decision struct {
	Allow   bool
	Audit   bool // true when allowed only because enforcement: audit
	Reason  string
	Matched *MatchedRule
}

// MatchedRule carries the allow-list entry that authorized L4.
type MatchedRule struct {
	ID         string
	Host       string
	Port       int
	AllowedIPs []string
	Rule       policy.AllowRule
}

// EgressRequest is a network attempt to authorize.
type EgressRequest struct {
	Host   string
	Port   int
	Binary string
}

// HTTPRequest is an application-layer request after L4 match.
type HTTPRequest struct {
	Host   string
	Port   int
	Method string
	Path   string
	Binary string
}

// PolicyEngine evaluates egress.
type PolicyEngine interface {
	Decide(ctx context.Context, req EgressRequest) (Decision, error)
	DecideHTTP(ctx context.Context, req HTTPRequest) (Decision, error)
	Apply(doc policy.Document) error
}

type compiledEndpoint struct {
	hasHost  bool
	pattern  hostpattern.Pattern
	ports    map[int]struct{}
	rule     policy.AllowRule
	ruleID   string
	binaries []string
}

// Allowlist is a default-deny host/port (+ optional L7) engine.
type Allowlist struct {
	doc        policy.Document
	endpoints  []compiledEndpoint
	topBins    []string
	anyRuleBin bool
	tofu       *tofu.Store
	rego       *RegoGate
}

// SetTOFU installs a trust-on-first-use store for binary fingerprints.
func (a *Allowlist) SetTOFU(s *tofu.Store) { a.tofu = s }

// Apply replaces the active policy document and compiles host patterns.
func (a *Allowlist) Apply(doc policy.Document) error {
	if err := doc.Validate(); err != nil {
		return err
	}
	var compiled []compiledEndpoint
	anyRuleBin := false
	for _, rule := range doc.AllowRules() {
		ep := compiledEndpoint{
			ports:    make(map[int]struct{}, len(rule.EffectivePorts())),
			rule:     rule,
			binaries: append([]string{}, rule.Binaries...),
		}
		if len(ep.binaries) > 0 {
			anyRuleBin = true
		}
		for _, p := range rule.EffectivePorts() {
			ep.ports[p] = struct{}{}
		}
		ep.ruleID = rule.ID
		if ep.ruleID == "" {
			ep.ruleID = rule.Host
		}
		if strings.TrimSpace(rule.Host) != "" {
			pat, err := hostpattern.Parse(rule.Host)
			if err != nil {
				return fmt.Errorf("policy engine: allow %q host %q: %w", rule.ID, rule.Host, err)
			}
			ep.hasHost = true
			ep.pattern = pat
		} else if len(rule.AllowedIPs) == 0 {
			return fmt.Errorf("policy engine: allow %q: host or allowed_ips required", rule.ID)
		}
		compiled = append(compiled, ep)
	}
	var gate *RegoGate
	if doc.RegoPath != "" {
		g, err := LoadRegoFile(doc.RegoPath)
		if err != nil {
			return fmt.Errorf("policy engine: rego_path: %w", err)
		}
		gate = g
	}
	a.doc = doc
	a.endpoints = compiled
	a.topBins = append([]string{}, doc.Binaries...)
	a.anyRuleBin = anyRuleBin
	a.rego = gate
	return nil
}

// Decide authorizes host:port (and optional binary). Default deny.
func (a *Allowlist) Decide(ctx context.Context, req EgressRequest) (Decision, error) {
	if err := a.gateBinary(req.Binary); err != nil {
		return Decision{Allow: false, Reason: err.Error()}, nil
	}
	ep, ok := a.matchL4(req)
	if !ok {
		return Decision{Allow: false, Reason: "default deny (no matching network.allow)"}, nil
	}
	dec := Decision{
		Allow:  true,
		Reason: "matched network.allow." + ep.ruleID + " " + displayHost(ep) + ":" + strconv.Itoa(req.Port),
		Matched: &MatchedRule{
			ID:         ep.ruleID,
			Host:       req.Host,
			Port:       req.Port,
			AllowedIPs: append([]string{}, ep.rule.AllowedIPs...),
			Rule:       ep.rule,
		},
	}
	if ok, reason := a.rego.Allow(ctx, req.Host, "", "", req.Binary); !ok {
		return Decision{Allow: false, Reason: reason, Matched: dec.Matched}, nil
	}
	return dec, nil
}

// DecideHTTP authorizes an HTTP method/path after L4 match.
func (a *Allowlist) DecideHTTP(ctx context.Context, req HTTPRequest) (Decision, error) {
	if err := a.gateBinary(req.Binary); err != nil {
		return Decision{Allow: false, Reason: err.Error()}, nil
	}
	ep, ok := a.matchL4(EgressRequest{Host: req.Host, Port: req.Port, Binary: req.Binary})
	if !ok {
		return Decision{Allow: false, Reason: "default deny (no matching network.allow)"}, nil
	}
	matched := &MatchedRule{
		ID:         ep.ruleID,
		Host:       req.Host,
		Port:       req.Port,
		AllowedIPs: append([]string{}, ep.rule.AllowedIPs...),
		Rule:       ep.rule,
	}
	allow, reason := ep.rule.MatchHTTP(req.Method, req.Path)
	if !allow {
		if ep.rule.IsAudit() {
			return Decision{
				Allow:   true,
				Audit:   true,
				Reason:  "audit: " + reason,
				Matched: matched,
			}, nil
		}
		return Decision{Allow: false, Reason: reason, Matched: matched}, nil
	}
	if ok, reason := a.rego.Allow(ctx, req.Host, req.Method, req.Path, req.Binary); !ok {
		if ep.rule.IsAudit() {
			return Decision{
				Allow:   true,
				Audit:   true,
				Reason:  "audit: " + reason,
				Matched: matched,
			}, nil
		}
		return Decision{Allow: false, Reason: reason, Matched: matched}, nil
	}
	return Decision{
		Allow:   true,
		Reason:  "matched network.allow." + ep.ruleID + " " + reason,
		Matched: matched,
	}, nil
}

func (a *Allowlist) gateBinary(binary string) error {
	if len(a.topBins) == 0 && !a.anyRuleBin {
		return nil
	}
	if strings.TrimSpace(binary) == "" {
		if len(a.topBins) > 0 && os.Getenv("OSG_REQUIRE_BINARY") == "1" {
			return fmt.Errorf("binary required by policy.binaries")
		}
		return nil
	}
	if len(a.topBins) > 0 && !binaryAllowed(a.topBins, binary) {
		return fmt.Errorf("binary %q not in policy.binaries", binary)
	}
	if a.tofu != nil {
		if _, err := a.tofu.VerifyOrCache(binary); err != nil {
			return err
		}
	}
	return nil
}

func (a *Allowlist) matchL4(req EgressRequest) (compiledEndpoint, bool) {
	for _, ep := range a.endpoints {
		if ep.hasHost {
			if !ep.pattern.Match(req.Host) {
				continue
			}
		} else if len(ep.rule.AllowedIPs) == 0 {
			continue
		}
		if _, ok := ep.ports[req.Port]; !ok {
			continue
		}
		if len(ep.binaries) > 0 {
			if req.Binary == "" {
				continue // rule restricted to binaries; skip when unknown
			}
			if !binaryAllowed(ep.binaries, req.Binary) {
				continue
			}
		}
		return ep, true
	}
	return compiledEndpoint{}, false
}

func displayHost(ep compiledEndpoint) string {
	if ep.hasHost {
		return ep.pattern.Source()
	}
	return "(allowed_ips)"
}

func binaryAllowed(allowed []string, binary string) bool {
	for _, a := range allowed {
		if a == "/**" || a == "*" || a == binary {
			return true
		}
		if ok, err := path.Match(a, binary); err == nil && ok {
			return true
		}
	}
	return false
}

var _ PolicyEngine = (*Allowlist)(nil)
