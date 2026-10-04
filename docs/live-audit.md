# Live-server audit mode

Static manifests describe what a server *should* expose. Live mode asks
the server itself. It connects over HTTP (streamable or legacy SSE) or
launches the server over stdio, runs the MCP initialize handshake, calls
`tools/list`, `resources/list`, and `prompts/list`, and audits what the
server actually answers with. Then it runs the full check suite against
that live-built manifest, plus four checks that only make sense against
a live transport.

## Quickstart

Against a server already running on your machine:

```bash
mcp-audit live --url http://127.0.0.1:8080/mcp
```

Against a server you launch yourself:

```bash
mcp-audit live --command "python my_server.py"
```

The same policy knobs as `scan` apply: `--format`, `--fail-on`,
`--config`.

## The auth probe is real

Before enumerating anything, live mode sends an **unauthenticated**
`initialize` + `tools/list`. If the server answers, the transport is
recorded as `auth_required: false, probed: true`, and the
`unauthenticated_exposure` check fires at **critical**. That is the
Ruflo failure mode (CVE-2026-59726): an MCP bridge answering strangers.

If the server answers 401/403 instead, the transport is recorded as
`auth_required: true`, and enumeration continues with your `--header`
credentials if you passed any:

```bash
mcp-audit live --url https://mcp.internal.example/sse \
  --header "Authorization: Bearer $MCP_TOKEN"
```

If the server demands auth and you passed no credentials, the audit
stops with a clear error instead of pretending the server is clean.

## Declaring the bind address

A probe cannot see how a server binds from the outside, so `--bind`
declares it:

```bash
mcp-audit live --url http://10.0.0.5:8080/mcp --bind 0.0.0.0
```

With `--bind 0.0.0.0`, the `exposed_bind` check fires, and
`network_tool_bridge` treats the surface as network-reachable. Without
`--bind`, reachability is derived from the URL host (anything that is
not localhost counts as reachable), and `exposed_bind` stays silent
rather than guessing.

## The four live-transport checks

| Check | Severity | What it catches |
|---|---|---|
| `unauthenticated_exposure` | critical (measured) / high (declared) | The server answered an unauthenticated probe, or the manifest declares no auth on a network transport |
| `exposed_bind` | high | Transport bound to 0.0.0.0 / :: (declared via `--bind`) |
| `dangerous_default_port` | low | Port is a commonly scanned default (3000, 5000, 8000, 8080, 9000, MCP Inspector 6274/6277); a discovery heuristic, not a verdict |
| `network_tool_bridge` | high | Network-reachable transport plus shell-execution or file-write tools in the live surface |

All four read the `transport` block on `manifest["server"]`. They are
inert on static manifests without one, so `mcp-audit scan` output does
not change.

## From Python

```python
from mcp_audit.live import LiveTarget, live_audit

report = live_audit(LiveTarget(url="http://127.0.0.1:8080/mcp", bind="0.0.0.0"))
for finding in report.findings:
    print(finding.severity, finding.target, finding.title)
```

## What live mode cannot see

- It never calls a tool, so `tools/call`-level auth is untested. A
  server can require auth on calls but not on listing, and the probe
  will call it open.
- It only exercises the four enumeration methods. Exotic transports
  (WebSocket, custom) are not supported.
- The bind address is always declared, never measured.
- Firewall rules and security groups are invisible to the probe; a
  "network-reachable" finding means reachable *as far as the probe can
  tell*.
