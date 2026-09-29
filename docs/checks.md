# Check catalog

Every check runs deterministically against the manifest. No model calls, no
network. Each check documents its own limitations in its docstring; this
page summarizes what each one looks for and how to fix what it finds.

| Check | Severity | What it catches |
|---|---|---|
| `description_injection` | high | Instruction-smuggling phrases in tool and prompt descriptions ("ignore previous instructions", fake system headers, secrecy clauses) |
| `broad_tool` | critical/high | Shell execution (critical), arbitrary file writes (high), unscoped network fetch (high) |
| `missing_auth` | medium | State-changing tools with no auth annotation |
| `dangerous_combo` | high | Tool pairs that together enable exfiltration (file reader + network sender) or download-and-execute (shell + network) |
| `sensitive_resource` | critical/high | Resources pointing at credentials, keys, or system directories |
| `prompt_template_injection` | high | Prompt templates with override-style language, or user input mixed into instruction-heavy text |
| `tool_impersonation` | medium | Names borrowing system/admin prefixes, sensitive command names, or vendor brands |
| `weak_input_schema` | medium | Security-sensitive string parameters (paths, URLs, commands) with no schema validation |
| `verbose_errors` | low | Descriptions or output schemas advertising stack traces and debug internals |
| `no_rate_limit` | low | Tools with no rate-limit annotation |
| `path_traversal` | high | File-reading tools with caller-supplied path parameters and no described traversal guard |
| `embedded_secret` | critical/high | API keys, passwords, or private key material baked into tool descriptions, resource URIs, or prompts |
| `approval_bypass` | high | Descriptions that nudge the agent to skip human approval ("auto-approve", "no need to ask", "trusted, no approval needed") |
| `credential_request` | high | Input schemas asking the caller to supply credentials (passwords, API keys, tokens) through parameters the model must fill |

## Reading a finding

Each finding carries:

- **severity**: critical, high, medium, or low. Sorted worst-first in every output format.
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
