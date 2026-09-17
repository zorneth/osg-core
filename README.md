<h1 align="center">osg-core</h1>

<p align="center">
  <strong>Policy & egress engine</strong><br>
  Canonical policy schema, L4/L7 allowlists, host patterns, TOFU, and env placeholders.
</p>
<p align="center">
  <a href="https://github.com/zorneth/osg-core/actions/workflows/ci.yml"><img src="https://github.com/zorneth/osg-core/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/zorneth/osg-core"><img src="https://pkg.go.dev/badge/github.com/zorneth/osg-core.svg" alt="Go Reference"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License"></a>
  <a href="https://github.com/zorneth/osg-core"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>
</p>
<p align="center">
  <sub>Part of the <a href="https://github.com/zorneth">zorneth / osg</a> ecosystem</sub>
</p>

---

## Overview

**osg-core** is the shared policy library for osg. Every data-plane and control-plane component evaluates egress and filesystem rules from this schema.

### Key Features

| Category | Capabilities |
|----------|--------------|
| **Schema** | `filesystem_policy`, `landlock`, `network_policies`, inference, display, credentials |
| **Engine** | Default-deny allowlist with L7 REST / GraphQL / MCP matching |
| **Hosts** | Glob host patterns (`**.example.com`), ports, binaries, credential binding |
| **Inference** | Builtin provider presets (`anthropic`, `openai`, `local` → `host.osg.internal`) |
| **Safety** | Binary TOFU store, env placeholder expansion for guest inject |

---

## Installation

```bash
go get github.com/zorneth/osg-core@latest
```

**Requirements:** Go 1.27+

---

## Quick Start

```go
package main

import (
    "fmt"

    "github.com/zorneth/osg-core/engine"
    "github.com/zorneth/osg-core/policy"
)

func main() {
    doc, err := policy.Load("policy.yaml")
    if err != nil {
        panic(err)
    }
    var al engine.Allowlist
    if err := al.Apply(doc); err != nil {
        panic(err)
    }
    d, _ := al.Decide(nil, engine.EgressRequest{Host: "api.github.com", Port: 443})
    fmt.Println(d.Allow, d.Reason)
}
```

---

## Package Structure

| Package | Purpose |
|---------|---------|
| `policy/` | Document load/validate, L7 rules, inference presets |
| `engine/` | `Allowlist` Decide / DecideHTTP |
| `hostpattern/` | Host glob matching |
| `tofu/` | Trust-on-first-use binary fingerprints |
| `env/` | Host→guest credential placeholder helpers |
| `defaults/` | Shared paths and image names |


---

## Related

| Resource | Link |
|----------|------|
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Organization | [https://github.com/zorneth](https://github.com/zorneth) |
| Organization overview | [github.com/zorneth](https://github.com/zorneth) |
| pkg.go.dev | [`github.com/zorneth/osg-core`](https://pkg.go.dev/github.com/zorneth/osg-core) |

## License

[MIT](./LICENSE) © zorneth
