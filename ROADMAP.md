# Roadmap — osg-core

Status: **v0.1.0-alpha.1** (alpha) · Part of [zorneth/osg](https://github.com/zorneth)

Shared policy schema and egress engine. Product-wide unfinished work lives in the workspace hub `docs/ROADMAP.md` (local multi-repo checkout).

## This module

| ID | Item | Notes |
|----|------|-------|
| C1 | **MCP / L7 depth** | First-class `protocol: mcp` method/tool matchers (hub R5) |
| C2 | **OPA / Rego polish** | Keep lightweight `rego_path` gate; document remote PDP contract (hub R4) |
| C3 | **Policy schema freeze** | Stabilize YAML for alpha consumers; versioned migration notes |
| C4 | **Engine concurrency** | Expand race tests around hot-reload + DecideHTTP |

## Non-goals (alpha)

- Embedding a full OPA SDK as the primary path
- Managed `inference.local` hostname rewrite

## Release

Cascade: tag **this repo first** — dependents require `v0.1.0-alpha.1`.
