# Scanning MCP client configs

Your MCP client config is a list of servers your client launches or
connects to on your behalf. A bad entry there runs attacker code every
time the client starts, or sends your agent's traffic somewhere it
should not go. `scan-config` reads those files and flags the risky
entries.

## Quickstart

```bash
mcp-audit scan-config
```

With no arguments it looks in the usual places: the Claude Desktop
config, `~/.cursor/mcp.json`, and `~/.claude.json`. To scan a specific
file (including a project's `.mcp.json`):

```bash
mcp-audit scan-config --path ./my-project/.mcp.json
```

Same policy knobs as `scan`: `--format`, `--fail-on`, `--config`.

## What it flags

| Check | Severity | What it catches |
|---|---|---|
| `config_remote_package` | high | stdio entry runs `npx`/`uvx`/`bunx` with an unpinned remote package: every client start downloads and runs whatever the registry serves today |
| `config_plaintext_secret` | medium | env var names that look like secrets (`API_KEY`, `TOKEN`, ...) in the plaintext JSON config |
| `config_unauthenticated_http` | high (remote) / medium (localhost) | HTTP/SSE entry with no Authorization header |
| `config_insecure_transport` | high | `http://` (not `https://`) to a non-localhost host |
| `config_shell_pipe` | high | command shaped like `curl <url> | sh`: the client executes whatever the URL serves, on every launch |

## Supported formats

The `mcpServers` map used by Claude Desktop, Cursor, and `.mcp.json`
project files. Claude Code's `~/.claude.json` is read when it carries a
top-level `mcpServers` map. Anything else is left alone rather than
guessed at.

## A note on secrets

The secret check flags *names*, not values: `MY_API_KEY` fires even if
the value is `YOUR_KEY_HERE`. That is deliberate. Real keys live in
these files often enough that the name alone is worth a nudge toward
the OS keychain or a secret manager, and the finding says when the name
looks like a placeholder.

## From Python

```python
from mcp_audit.client_config import scan_client_config, scan_discovered_configs

report = scan_client_config("~/.cursor/mcp.json")
for found in scan_discovered_configs():
    source, path, report = found
    print(source, path, report.highest_severity())
```

Everything is local file reads. Nothing is sent anywhere.
