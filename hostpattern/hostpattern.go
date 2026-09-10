// Copyright 2026 the osg-port authors
// SPDX-License-Identifier: Apache-2.0
//
// Host-pattern matching semantics adapted from NVIDIA OpenShell
// (crates/openshell-core/src/host_pattern.rs), Apache-2.0.

// Package hostpattern implements DNS-label-aware host globs used by network policy.
//
// Matching is case-insensitive. A '*' wildcard stays within one DNS label,
// while a label consisting only of '**' consumes one or more labels — same
// idea as OpenShell / Rego glob.match with a '.' delimiter.
package hostpattern

import (
	"fmt"
	"path"
	"strings"
	"unicode"
)

// Pattern is a validated, compiled DNS host pattern.
type Pattern struct {
	source string
	labels []labelPattern
}

type labelKind int

const (
	labelRecursive labelKind = iota
	labelGlob
)

type labelPattern struct {
	kind    labelKind
	source  string // original label (lowercase); only for labelGlob
	literal bool
}

// Parse validates and compiles a host pattern.
func Parse(pattern string) (Pattern, error) {
	if pattern == "" {
		return Pattern{}, fmt.Errorf("host pattern must not be empty")
	}
	for _, r := range pattern {
		if unicode.IsSpace(r) {
			return Pattern{}, fmt.Errorf("host pattern must not contain whitespace")
		}
		if r == '{' || r == '}' {
			return Pattern{}, fmt.Errorf("host pattern must not contain brace alternates; list each host pattern separately")
		}
	}

	source := strings.ToLower(pattern)
	parts := strings.Split(source, ".")
	for _, p := range parts {
		if p == "" {
			return Pattern{}, fmt.Errorf("host pattern must not contain empty DNS labels")
		}
	}

	labels := make([]labelPattern, 0, len(parts))
	for _, label := range parts {
		if label == "**" {
			labels = append(labels, labelPattern{kind: labelRecursive})
			continue
		}
		// Reject '**' embedded inside a label (e.g. api**.example.com).
		if strings.Contains(label, "**") {
			return Pattern{}, fmt.Errorf("invalid host pattern: '**' must be an entire DNS label")
		}
		if _, err := path.Match(label, "x"); err != nil {
			return Pattern{}, fmt.Errorf("invalid host pattern: %w", err)
		}
		literal := !strings.ContainsAny(label, "*?[")
		labels = append(labels, labelPattern{kind: labelGlob, source: label, literal: literal})
	}
	return Pattern{source: source, labels: labels}, nil
}

// Source returns the normalized (lowercase) pattern string.
func (p Pattern) Source() string { return p.source }

// Match reports whether host matches this pattern.
func (p Pattern) Match(host string) bool {
	host = strings.ToLower(host)
	labels := strings.Split(host, ".")
	return p.matchLabels(labels)
}

func (p Pattern) matchLabels(host []string) bool {
	for _, l := range host {
		if l == "" {
			return false
		}
	}
	type state struct{ pi, hi int }
	pending := []state{{0, 0}}
	visited := map[state]struct{}{}
	for len(pending) > 0 {
		n := len(pending) - 1
		cur := pending[n]
		pending = pending[:n]
		if _, ok := visited[cur]; ok {
			continue
		}
		visited[cur] = struct{}{}
		if cur.pi == len(p.labels) && cur.hi == len(host) {
			return true
		}
		if cur.pi >= len(p.labels) {
			continue
		}
		lab := p.labels[cur.pi]
		switch lab.kind {
		case labelRecursive:
			if cur.hi < len(host) {
				pending = append(pending, state{cur.pi + 1, cur.hi + 1}, state{cur.pi, cur.hi + 1})
			}
		case labelGlob:
			if cur.hi < len(host) {
				ok, err := path.Match(lab.source, host[cur.hi])
				if err == nil && ok {
					pending = append(pending, state{cur.pi + 1, cur.hi + 1})
				}
			}
		}
	}
	return false
}

// MatchString parses pattern and matches host (one-shot helper).
func MatchString(pattern, host string) (bool, error) {
	p, err := Parse(pattern)
	if err != nil {
		return false, err
	}
	return p.Match(host), nil
}
