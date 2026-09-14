package engine

import (
	"bufio"
	"context"
	"os"
	"path"
	"strings"
)

// RegoGate is an optional post-allow deny hook.
// Supports lightweight osg-rego lines and a subset of Rego equality checks:
//
//	# osg-rego
//	deny host evil.example.com
//	deny method DELETE
//	deny path /admin/**
//
//	allow = false { input.host == "evil.example.com" }
//
// Missing/empty path = no-op (Go policy only).
type RegoGate struct {
	denyHosts   []string
	denyMethods []string
	denyPaths   []string
}

// LoadRegoFile loads an optional deny-list Rego/osg-rego file.
func LoadRegoFile(pathName string) (*RegoGate, error) {
	pathName = strings.TrimSpace(pathName)
	if pathName == "" {
		return nil, nil
	}
	f, err := os.Open(pathName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	g := &RegoGate{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "package ") || strings.HasPrefix(line, "default ") || strings.HasPrefix(line, "import ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.EqualFold(fields[0], "deny") {
			switch strings.ToLower(fields[1]) {
			case "host":
				g.denyHosts = append(g.denyHosts, fields[2])
			case "method":
				g.denyMethods = append(g.denyMethods, strings.ToUpper(fields[2]))
			case "path":
				g.denyPaths = append(g.denyPaths, fields[2])
			}
		}
		if strings.Contains(line, "input.host") && strings.Contains(line, "==") {
			if q := extractQuoted(line); q != "" {
				g.denyHosts = append(g.denyHosts, q)
			}
		}
		if strings.Contains(line, "input.method") && strings.Contains(line, "==") {
			if q := extractQuoted(line); q != "" {
				g.denyMethods = append(g.denyMethods, strings.ToUpper(q))
			}
		}
		if strings.Contains(line, "input.path") && strings.Contains(line, "==") {
			if q := extractQuoted(line); q != "" {
				g.denyPaths = append(g.denyPaths, q)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return g, nil
}

func extractQuoted(s string) string {
	for _, quote := range []byte{'"', '\''} {
		i := strings.IndexByte(s, quote)
		if i < 0 {
			continue
		}
		j := strings.IndexByte(s[i+1:], quote)
		if j < 0 {
			continue
		}
		return s[i+1 : i+1+j]
	}
	return ""
}

// Allow reports whether the request passes the Rego gate (true = keep Go allow).
func (g *RegoGate) Allow(_ context.Context, host, method, pathName, _ string) (bool, string) {
	if g == nil {
		return true, ""
	}
	for _, h := range g.denyHosts {
		if strings.EqualFold(h, host) {
			return false, "rego deny host " + h
		}
	}
	method = strings.ToUpper(method)
	for _, m := range g.denyMethods {
		if m == method {
			return false, "rego deny method " + m
		}
	}
	for _, p := range g.denyPaths {
		if matchRegoPath(p, pathName) {
			return false, "rego deny path " + p
		}
	}
	return true, ""
}

func matchRegoPath(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return name == prefix || strings.HasPrefix(name, prefix+"/")
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}
