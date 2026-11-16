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

With no arguments it looks in the usual places (the table below). To
scan a specific file (including a project's `.mcp.json`):

```bash
mcp-audit scan-config --path ./my-project/.mcp.json
```

Same policy knobs as `scan`: `--format`, `--fail-on`, `--config`. The
report format is the same whatever client wrote the file.

## Where each client keeps its config

| Client | Location | Notes |
|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%/Claude/claude_desktop_config.json` (Windows), `~/.config/Claude/claude_desktop_config.json` (Linux) | |
| Cursor (global) | `~/.cursor/mcp.json` | Applies to every project |
| Cursor (project) | `.cursor/mcp.json` in the project root | Checked in with the project, so a risky entry reaches every teammate who opens it |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | Global only; remote servers are spelled `serverUrl` |
| Windsurf (Devin Desktop) | `~/.config/devin/mcp_config.json` (macOS and Linux), `%APPDATA%/devin/mcp_config.json` (Windows) | Windsurf was renamed Devin Desktop in 2026; installs from before the rename keep the `.codeium` path, so both are searched |
| Claude Code | `~/.claude.json` | Read when it carries a top-level `mcpServers` map |
| Claude Code (project) | `.mcp.json` in the project root | |

If two locations point at the same file, it is scanned once, under
the first label in the table order.

## What it flags

| Check | Severity | What it catches |
|---|---|---|
| `config_remote_package` | high | stdio entry runs `npx`/`uvx`/`bunx` with an unpinned remote package: every client start downloads and runs whatever the registry serves today |
| `config_plaintext_secret` | medium | env var names that look like secrets (`API_KEY`, `TOKEN`, ...) in the plaintext JSON config, on stdio and remote entries alike |
| `config_unauthenticated_http` | high (remote) / medium (localhost) | HTTP/SSE entry with no Authorization header |
| `config_insecure_transport` | high | `http://` (not `https://`) to a non-localhost host |
| `config_shell_pipe` | high | command shaped like `curl <url> | sh`: the client executes whatever the URL serves, on every launch |

## Supported formats

The `mcpServers` map used by Claude Desktop, Cursor, Windsurf, and
`.mcp.json` project files. Two spelling differences in the wild are
normalized before the checks run:

- Windsurf writes the remote URL as `serverUrl`, not `url` (some
  tools emit `httpUrl` instead). All three spellings become the same
  remote entry. Before this was handled, a Windsurf remote entry
  looked like it had no transport at all, and every remote check
  stayed silent on it.
- Cursor and Windsurf often spell the transport as `type` (`sse`,
  `streamable-http`) instead of `transport`. `streamable-http`
  normalizes to `http` so the remote checks recognize it.

An entry marked `"disabled": true` is still scanned. Disabling is
one click in the client, and a plaintext secret in the file is in
the file whether the server currently runs or not.

Anything that is not an `mcpServers` map is left alone rather than
guessed at.

Sample files live in `examples/client-configs/`:
`windsurf_mcp_config.json` (a Windsurf config that trips four of the
five checks) and `cursor_project_mcp.json` (a clean project config).
Try them:

```bash
mcp-audit scan-config --path examples/client-configs/windsurf_mcp_config.json
mcp-audit scan-config --path examples/client-configs/cursor_project_mcp.json
```

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
report = scan_client_config(
    "~/.codeium/windsurf/mcp_config.json", source_label="windsurf"
)
for found in scan_discovered_configs():
    source, path, report = found
    print(source, path, report.highest_severity())
```

Everything is local file reads. Nothing is sent anywhere.
