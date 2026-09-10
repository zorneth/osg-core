// Package engine evaluates egress decisions against a policy.Document.
package engine

import (
	"context"
	"fmt"
	"path"
	"strconv"

	"github.com/lkmavi/osg-core/hostpattern"
	"github.com/lkmavi/osg-core/policy"
)

// Decision is admit / deny for one request.
type Decision struct {
	Allow  bool
	Reason string
}

// EgressRequest is a network attempt to authorize.
type EgressRequest struct {
	Host   string
	Port   int
	Binary string
}

// PolicyEngine evaluates egress.
type PolicyEngine interface {
	Decide(ctx context.Context, req EgressRequest) (Decision, error)
	Apply(doc policy.Document) error
}

type compiledEndpoint struct {
	pattern  hostpattern.Pattern
	ports    map[int]struct{}
	ruleID   string
	binaries []string
}

// Allowlist is a default-deny host/port engine.
type Allowlist struct {
	doc       policy.Document
	endpoints []compiledEndpoint
}

// Apply replaces the active policy document and compiles host patterns.
func (a *Allowlist) Apply(doc policy.Document) error {
	if err := doc.Validate(); err != nil {
		return err
	}
	var compiled []compiledEndpoint
	for _, rule := range doc.AllowRules() {
		pat, err := hostpattern.Parse(rule.Host)
		if err != nil {
			return fmt.Errorf("policy engine: allow %q host %q: %w", rule.ID, rule.Host, err)
		}
		ports := make(map[int]struct{}, len(rule.EffectivePorts()))
		for _, p := range rule.EffectivePorts() {
			ports[p] = struct{}{}
		}
		id := rule.ID
		if id == "" {
			id = rule.Host
		}
		compiled = append(compiled, compiledEndpoint{
			pattern:  pat,
			ports:    ports,
			ruleID:   id,
			binaries: append([]string{}, rule.Binaries...),
		})
	}
	a.doc = doc
	a.endpoints = compiled
	return nil
}

// Decide authorizes host:port (and optional binary). Default deny.
func (a *Allowlist) Decide(_ context.Context, req EgressRequest) (Decision, error) {
	for _, ep := range a.endpoints {
		if !ep.pattern.Match(req.Host) {
			continue
		}
		if _, ok := ep.ports[req.Port]; !ok {
			continue
		}
		if len(ep.binaries) > 0 && req.Binary != "" && !binaryAllowed(ep.binaries, req.Binary) {
			continue
		}
		return Decision{
			Allow:  true,
			Reason: "matched network.allow." + ep.ruleID + " " + ep.pattern.Source() + ":" + strconv.Itoa(req.Port),
		}, nil
	}
	return Decision{Allow: false, Reason: "default deny (no matching network.allow)"}, nil
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
