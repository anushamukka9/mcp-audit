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

These checks read the manifest, not the server. They cannot verify that
auth is enforced server-side, that a resource is actually served, or that
input validation exists beyond the schema. A finding is a pointer that says
"look here", not a verdict. The honest-limitations section in the README
has the full list.
