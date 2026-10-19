# Check catalog

Every check runs deterministically against the manifest. No model calls, no
network. Each check documents its own limitations in its docstring; this
page summarizes what each one looks for, how severe it is, and why.

The severity column is never a bare label: every check carries a
`severity_rationale`, one or two sentences explaining the rating, which
also ships in each finding (`Finding.severity_rationale`, the JSON
`severity_rationale` field, and the markdown/HTML reports).

| Check | Severity | What it catches | Why that severity |
|---|---|---|---|
| `description_injection` | high | Instruction-smuggling phrases in tool and prompt descriptions ("ignore previous instructions", fake system headers, secrecy clauses) | Descriptions are model-visible on every tool offer; one bad description can steer every session |
| `broad_tool` | critical/high | Shell execution (critical), arbitrary file writes (high), unscoped network fetch (high) | Shell execution turns any prompt injection into remote code execution; writes and unscoped fetch need a second step |
| `missing_auth` | medium | State-changing tools with no auth annotation | Often a documentation gap rather than a real hole; the check cannot verify server-side enforcement |
| `dangerous_combo` | high | Tool pairs that together enable exfiltration (file reader + network sender) or download-and-execute (shell + network) | The pair is a complete attack path, one prompt injection away |
| `sensitive_resource` | critical/high | Resources pointing at credentials, keys, or system directories | Resources are model-readable by design; exposure of key material means disclosure |
| `prompt_template_injection` | high | Prompt templates with override-style language, or user input mixed into instruction-heavy text | Templates run with model privileges; override language baked in is an attack the server ships to itself |
| `tool_impersonation` | medium | Names borrowing system/admin prefixes, sensitive command names, or vendor brands | Name confusion aids social engineering but is not an exploit on its own |
| `weak_input_schema` | medium | Security-sensitive string parameters (paths, URLs, commands) with no schema validation | Schema-level only; the check cannot see server-side validation |
| `verbose_errors` | low | Descriptions or output schemas advertising stack traces and debug internals | Mild information disclosure; helps debugging more than it helps attackers |
| `no_rate_limit` | low | Tools with no rate-limit annotation | Hygiene; enables abuse but creates no attack path alone |
| `path_traversal` | high | File-reading tools with caller-supplied path parameters and no described traversal guard | Caller-supplied paths into file reads are the classic traversal shape |
| `embedded_secret` | critical/high | API keys, passwords, or private key material baked into tool descriptions, resource URIs, or prompts | A real key in the manifest is exposed to everyone who can read it |
| `approval_bypass` | high | Descriptions that nudge the agent to skip human approval ("auto-approve", "no need to ask", "trusted, no approval needed") | The description votes on its own trust when clients decide whether to ask the user |
| `credential_request` | high | Input schemas asking the caller to supply credentials (passwords, API keys, tokens) through parameters the model must fill | Normalizes credential harvesting; on a malicious server it is a phishing kit |
| `elevated_privilege` | high/medium | Privilege claims (root/sudo/bypassed checks, high) and over-broad scope (wildcard resources, "any file", medium) | Privilege multiplies every other finding's blast radius; broad scope is risky but often the tool's job |
| `exfiltration_path` | high | A sensitive resource on a server that also ships a network-capable tool | Complete path from secret to network with no reader tool needed |
| `privilege_mixing` | medium | Some state-changing tools carry auth annotations while others do not | Inconsistency means missing access control or missing documentation; the owner must say which |
| `prompt_reads_sensitive` | high | Prompt templates referencing sensitive file paths or instructing the model to read secrets | Templates run with model privileges and their output goes back to the user |
| `unauthenticated_exposure` | critical/high | Network transport answered an unauthenticated probe (critical), or the manifest declares no auth on a network transport (high) | The Ruflo failure mode (CVE-2026-59726): an MCP bridge answering strangers is remote code execution by invitation |
| `exposed_bind` | high | Transport bound to 0.0.0.0 / ::, declared via `--bind` | A wide bind turns every other weakness into a remote one |
| `dangerous_default_port` | low | Port is a commonly scanned default (3000, 5000, 8000, 8080, 9000, MCP Inspector 6274/6277) | Discovery heuristic only; the port alone creates no attack path |
| `network_tool_bridge` | high | Network-reachable transport plus shell-execution or file-write tools in the surface | Remote reachability paired with the tool shapes that turn access into control |
| `config_remote_package` | high | Client config runs `npx`/`uvx`/`bunx` with an unpinned remote package | Every client start executes whatever the registry serves today, with your privileges |
| `config_plaintext_secret` | medium | Secret-looking env var names in a plaintext client config | The file gets backed up, synced, and pasted into support threads |
| `config_unauthenticated_http` | high/medium | Client config points at an HTTP/SSE server with no auth header (high off localhost, medium on it) | Unauthenticated calls crossing a real network carry no identity |
| `config_insecure_transport` | high | `http://` to a non-localhost MCP server | Tool traffic, including credentials in parameters, is readable to anyone on the path |
| `config_shell_pipe` | high | Client config command shaped like `curl <url> | sh` | Remote code execution by design, on every launch |

The live-transport checks (`unauthenticated_exposure`, `exposed_bind`,
`dangerous_default_port`, `network_tool_bridge`) read the `transport`
block on `manifest["server"]`, which `mcp-audit live` fills in from a
real probe. They stay silent on static manifests. The `config_*`
checks read the `client_servers` list built by
`mcp_audit.client_config.scan_client_config`, and stay silent on
ordinary server manifests. See [live-audit.md](live-audit.md) and
[client-config.md](client-config.md).

The `known_vulnerable_package` check is the one check that does not
reason about manifest shape: it compares declared package names
(server block, `dependencies`, client-config runner specs) against a
CVE feed. The bundled feed is an offline snapshot; `--cve-feed` swaps
in your own. See [cve-feed.md](cve-feed.md).

Per-check severity can be tuned without forking the checks: see
`severity_overrides` in [configuration.md](configuration.md).

## Reading a finding

Each finding carries:

- **severity**: critical, high, medium, or low. Sorted worst-first in every output format.
- **severity_rationale**: why the finding got that severity, in plain language.
- **target**: what was flagged, as `tool:name`, `resource:name`, `prompt:name`, or `server:a + b` for pair findings.
- **title**: one line saying what is wrong.
- **explanation**: why it matters, in plain language.
- **remediation**: what to do about it.

## What the checks cannot see

The static checks read the manifest, not the server. They cannot verify that
auth is enforced server-side, that a resource is actually served, or that
input validation exists beyond the schema. A finding is a pointer that says
"look here", not a verdict. The honest-limitations section in the README
has the full list.

Live mode closes part of that gap: `mcp-audit live` enumerates a running
server and *measures* whether its transport answers without auth. But the
live probe never calls a tool, so `tools/call`-level auth stays untested,
and the bind address is always declared, never measured. See
[live-audit.md](live-audit.md) for the full list.
