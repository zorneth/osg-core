# osg-core

MIT — **product** policy model, host patterns, and egress engine.

Canonical YAML is **ours** (`filesystem`, `network.allow`, `display`, …).  
OpenShell-shaped documents (`filesystem_policy`, `network_policies`, …) are still **accepted** via an importer for migration — see `policy.Parse`.

Compat / Apache lane for frozen OpenShell-shaped types: `osg-port-core`.

```bash
cd /path/to/agent-blocker
export GOWORK=$PWD/go.work
go test -C osg-core ./...
```
