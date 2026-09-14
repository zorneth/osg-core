package policy

import (
	"path"
	"strings"
)

// L7 protocols supported in product schema (P9 MVP: rest; others reserved).
const (
	ProtocolREST      = "rest"
	ProtocolWebsocket = "websocket"
	ProtocolGraphQL   = "graphql"
	ProtocolMCP       = "mcp"
)

// TLS modes.
const (
	TLSTerminate   = "terminate"
	TLSPassthrough = "passthrough"
)

// Access presets expand into method/path allow rules.
const (
	AccessReadOnly  = "read-only"
	AccessReadWrite = "read-write"
	AccessFull      = "full"
)

// L7Rule wraps an allow rule.
type L7Rule struct {
	Allow *L7Allow `yaml:"allow,omitempty" json:"allow,omitempty"`
}

// L7Allow matches one HTTP (or MCP/GraphQL) request.
type L7Allow struct {
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	Path   string `yaml:"path,omitempty" json:"path,omitempty"`
	// Tool matches MCP tools/call params.name (glob). Empty = any tool.
	Tool string `yaml:"tool,omitempty" json:"tool,omitempty"`
}

// L7DenyRule blocks matching requests (checked before allows).
type L7DenyRule struct {
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	Path   string `yaml:"path,omitempty" json:"path,omitempty"`
	Tool   string `yaml:"tool,omitempty" json:"tool,omitempty"`
}

// NeedsL7 reports whether the rule requires application-layer inspection.
func (r AllowRule) NeedsL7() bool {
	proto := strings.ToLower(strings.TrimSpace(r.Protocol))
	if proto == "" {
		return false
	}
	if strings.TrimSpace(r.Access) != "" {
		return true
	}
	if len(r.Rules) > 0 || len(r.DenyRules) > 0 {
		return true
	}
	return proto == ProtocolREST || proto == ProtocolWebsocket || proto == ProtocolGraphQL || proto == ProtocolMCP
}

// MethodWebsocketText is the synthetic L7 method for client→server WS text frames.
const MethodWebsocketText = "WEBSOCKET_TEXT"

// MethodSubscribe is the synthetic L7 method for GraphQL-over-WS subscribe/start.
const MethodSubscribe = "subscribe"

// ExpandedL7Allows returns explicit allow rules, expanding access presets when set.
// Endpoint Path scopes preset paths when non-empty.
func (r AllowRule) ExpandedL7Allows() []L7Allow {
	if len(r.Rules) > 0 {
		var out []L7Allow
		for _, rule := range r.Rules {
			if rule.Allow == nil {
				continue
			}
			a := *rule.Allow
			if a.Path == "" {
				a.Path = defaultL7Path(r.Path)
			}
			out = append(out, a)
		}
		return out
	}
	access := strings.ToLower(strings.TrimSpace(r.Access))
	if access == "" {
		return nil
	}
	basePath := defaultL7Path(r.Path)
	proto := strings.ToLower(strings.TrimSpace(r.Protocol))
	switch proto {
	case ProtocolWebsocket:
		switch access {
		case AccessReadOnly:
			return []L7Allow{{Method: "GET", Path: basePath}}
		case AccessReadWrite:
			return []L7Allow{
				{Method: "GET", Path: basePath},
				{Method: MethodWebsocketText, Path: basePath},
			}
		case AccessFull:
			return []L7Allow{{Method: "*", Path: basePath}}
		default:
			return nil
		}
	case ProtocolGraphQL:
		switch access {
		case AccessReadOnly:
			return []L7Allow{{Method: "GET", Path: basePath}}
		case AccessReadWrite, AccessFull:
			return []L7Allow{
				{Method: "GET", Path: basePath},
				{Method: MethodSubscribe, Path: basePath},
			}
		default:
			return nil
		}
	case ProtocolMCP:
		switch access {
		case AccessReadOnly:
			return []L7Allow{
				{Method: "initialize", Path: basePath},
				{Method: "tools/list", Path: basePath},
				{Method: "resources/list", Path: basePath},
				{Method: "resources/read", Path: basePath},
				{Method: "prompts/list", Path: basePath},
			}
		case AccessReadWrite:
			return []L7Allow{
				{Method: "initialize", Path: basePath},
				{Method: "tools/list", Path: basePath},
				{Method: "tools/call", Path: basePath},
				{Method: "resources/list", Path: basePath},
				{Method: "resources/read", Path: basePath},
				{Method: "prompts/list", Path: basePath},
			}
		case AccessFull:
			return []L7Allow{{Method: "*", Path: basePath}}
		default:
			return nil
		}
	}
	switch access {
	case AccessReadOnly:
		return []L7Allow{
			{Method: "GET", Path: basePath},
			{Method: "HEAD", Path: basePath},
			{Method: "OPTIONS", Path: basePath},
		}
	case AccessReadWrite:
		return []L7Allow{
			{Method: "GET", Path: basePath},
			{Method: "HEAD", Path: basePath},
			{Method: "OPTIONS", Path: basePath},
			{Method: "POST", Path: basePath},
			{Method: "PUT", Path: basePath},
			{Method: "PATCH", Path: basePath},
		}
	case AccessFull:
		return []L7Allow{{Method: "*", Path: basePath}}
	default:
		return nil
	}
}

func defaultL7Path(endpointPath string) string {
	p := strings.TrimSpace(endpointPath)
	if p == "" {
		return "/**"
	}
	return p
}

// MatchL7Path matches an HTTP path against a policy glob (* = one segment, ** = any).
func MatchL7Path(pattern, reqPath string) bool {
	pat := normalizeURLPath(pattern)
	p := normalizeURLPath(reqPath)
	if pat == "/**" || pat == "**" {
		return true
	}
	return matchPathGlob(pat, p)
}

func normalizeURLPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Keep trailing semantics soft: Clean collapses // and .
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		return clean + "/"
	}
	return clean
}

func matchPathGlob(pattern, req string) bool {
	if pattern == req {
		return true
	}
	if ok, err := path.Match(pattern, req); err == nil && ok {
		return true
	}
	// ** support: split on /**/
	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		if len(parts) == 1 {
			return false
		}
		// prefix ** suffix (possibly multiple **)
		cur := req
		for i, part := range parts {
			if part == "" {
				if i == len(parts)-1 {
					return true
				}
				continue
			}
			if i == 0 {
				if !strings.HasPrefix(cur, part) {
					return false
				}
				cur = cur[len(part):]
				continue
			}
			idx := strings.Index(cur, part)
			if idx < 0 {
				return false
			}
			cur = cur[idx+len(part):]
			if i == len(parts)-1 {
				return cur == "" || part == "" || strings.HasPrefix(part, "/")
			}
		}
		return cur == ""
	}
	return false
}

// MatchHTTP reports whether method+path is allowed under this rule's L7 policy.
// L4-only rules (no L7) allow any method/path.
// For MCP, method is the JSON-RPC method and reqPath may be "method\x00tool".
func (r AllowRule) MatchHTTP(method, reqPath string) (allow bool, reason string) {
	if !r.NeedsL7() {
		return true, "l4-only"
	}
	method = strings.TrimSpace(method)
	tool := ""
	pathOnly := reqPath
	if strings.EqualFold(strings.TrimSpace(r.Protocol), ProtocolMCP) {
		method = strings.TrimSpace(method)
		if i := strings.IndexByte(reqPath, 0); i >= 0 {
			pathOnly = reqPath[:i]
			tool = reqPath[i+1:]
		}
		if pathOnly == "" {
			pathOnly = defaultL7Path(r.Path)
		}
	} else {
		method = strings.ToUpper(method)
	}
	for _, d := range r.DenyRules {
		if mcpOrHTTPMethodMatch(r.Protocol, d.Method, method) && MatchL7Path(defaultL7Path(d.Path), pathOnly) && toolMatches(d.Tool, tool) {
			return false, "matched deny_rules"
		}
	}
	allows := r.ExpandedL7Allows()
	if len(allows) == 0 {
		return false, "l7 configured but no allow rules"
	}
	for _, a := range allows {
		if mcpOrHTTPMethodMatch(r.Protocol, a.Method, method) && MatchL7Path(defaultL7Path(a.Path), pathOnly) && toolMatches(a.Tool, tool) {
			return true, "matched l7 allow"
		}
	}
	return false, "no matching l7 allow"
}

func mcpOrHTTPMethodMatch(protocol, pat, method string) bool {
	if strings.EqualFold(strings.TrimSpace(protocol), ProtocolMCP) {
		pat = strings.TrimSpace(pat)
		method = strings.TrimSpace(method)
		if pat == "" || pat == "*" {
			return true
		}
		return pat == method
	}
	return methodMatches(pat, method)
}

func toolMatches(pat, tool string) bool {
	pat = strings.TrimSpace(pat)
	if pat == "" || pat == "*" {
		return true
	}
	if tool == "" {
		return false
	}
	if ok, err := path.Match(pat, tool); err == nil && ok {
		return true
	}
	return pat == tool
}

func methodMatches(pat, method string) bool {
	pat = strings.ToUpper(strings.TrimSpace(pat))
	if pat == "" || pat == "*" {
		return true
	}
	return pat == method
}
