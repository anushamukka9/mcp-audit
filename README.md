# mcp-audit

Security auditing for MCP servers. Point it at your server's tool,
resource, and prompt manifest and it flags the issues it can see
statically: injected instructions in descriptions, over-broad tools,
dangerous tool pairs, exposed secrets, and more. Deterministic, no model
calls, no network.

## Why this exists

MCP servers hand the model tools, and every tool is attack surface. A tool
description is model-visible text, which makes it a quiet channel for
prompt injection. A file reader plus a webhook sender is an exfiltration
kit wearing a trench coat. Nobody was checking for any of this in a
systematic way, so I wrote the checker I wanted to run against my own
servers.

The contract is strict on purpose: everything is pattern matching over the
manifest. That means it answers in milliseconds, it never phones home with
your server definition, and its behavior is fully readable in the source.
It also means it cannot see what the manifest does not say. Read the
honest limitations before you trust it with anything important.

## Quickstart

```bash
pip install mcp-audit
```

```bash
$ mcp-audit scan manifest.json

mcp-audit: acme-ops-server - 18 finding(s)
severity: critical=3, high=4, medium=6, low=5

[CRITICAL] tool:run_shell
           Tool 'run_shell' allows arbitrary shell execution (broad_tool)
[CRITICAL] resource:app-env
           Resource 'app-env' points at credentials or keys (sensitive_resource)
[HIGH    ] server:run_shell + post_webhook
           Download-and-execute pair: 'run_shell' runs commands, 'post_webhook' reaches the network (dangerous_combo)
...
```

Or from Python:

```python
from mcp_audit import AuditPolicy, audit_server

report = audit_server(manifest)
for finding in report.findings:
    print(finding.severity, finding.target, finding.title)
    print("  why:", finding.explanation)
    print("  fix:", finding.remediation)

policy = AuditPolicy(fail_on="high", allowlist={"no_rate_limit": ["tool:search_docs"]})
report = audit_server(manifest, policy=policy)
print("passed:", policy.passes(report))
```

Machine-readable output for CI:

```bash
mcp-audit scan manifest.json --format json      # JSON report
mcp-audit scan manifest.json --format sarif     # GitHub code scanning
mcp-audit scan manifest.json --format markdown  # paste into a PR
```

Try it on the bundled examples: `examples/vulnerable_manifest.json` (18
findings on purpose) and `examples/clean_manifest.json` (zero findings,
and a decent template for how to write a manifest).

## Checks

| Check | Severity | What it catches |
|---|---|---|
| `description_injection` | high | Instruction smuggling in tool/prompt descriptions ("ignore previous instructions", fake system headers, secrecy clauses) |
| `broad_tool` | critical/high | Arbitrary shell execution (critical), unrestricted file writes (high), unscoped network fetch (high) |
| `missing_auth` | medium | State-changing tools with no auth annotation |
| `dangerous_combo` | high | Tool pairs that enable exfiltration or download-and-execute |
| `sensitive_resource` | critical/high | Resources pointing at credentials, keys, or system directories |
| `prompt_template_injection` | high | Override-style language in prompt templates, or user input mixed into instruction-heavy text |
| `tool_impersonation` | medium | Names borrowing system/admin prefixes or vendor brands |
| `weak_input_schema` | medium | Path/URL/command parameters with no schema validation |
| `verbose_errors` | low | Stack traces and debug internals in descriptions or output schemas |
| `no_rate_limit` | low | Tools with no rate-limit annotation |
| `path_traversal` | high | File-reading tools with caller-supplied paths and no described traversal guard |
| `embedded_secret` | critical/high | API keys, passwords, and key material baked into the manifest itself |

Every check documents its limitations in its docstring. See
[docs/checks.md](docs/checks.md) for the full catalog.

Tune the noise with a policy file: `fail_on` thresholds, disabled checks,
and per-check allowlists. See [docs/configuration.md](docs/configuration.md).

## Benchmarks

Each check ships with labeled manifests under `benchmarks/` (vulnerable and
clean, including near-miss cases). Run them yourself:

```bash
python -m mcp_audit.benchmark
```

Results on the bundled set (16 manifests, 26 check activations):

| check | n | precision | recall | F1 |
|---|---|---|---|---|
| description_injection | 2 | 1.00 | 1.00 | 1.00 |
| broad_tool | 4 | 1.00 | 1.00 | 1.00 |
| missing_auth | 4 | 1.00 | 1.00 | 1.00 |
| dangerous_combo | 1 | 1.00 | 1.00 | 1.00 |
| sensitive_resource | 2 | 1.00 | 1.00 | 1.00 |
| prompt_template_injection | 2 | 1.00 | 1.00 | 1.00 |
| tool_impersonation | 1 | 1.00 | 1.00 | 1.00 |
| weak_input_schema | 4 | 1.00 | 1.00 | 1.00 |
| verbose_errors | 1 | 1.00 | 1.00 | 1.00 |
| no_rate_limit | 3 | 1.00 | 1.00 | 1.00 |
| path_traversal | 1 | 1.00 | 1.00 | 1.00 |
| embedded_secret | 1 | 1.00 | 1.00 | 1.00 |

Take these numbers for what they are: a smoke test proving the patterns
fire on the obvious cases, not a security certification. The set is small
and hand-written. Real servers are more creative than any labeled set. If
you evaluate against your own manifests, please contribute the cases back.

## CI usage

Fail the build or upload SARIF to code scanning. See
[docs/ci-usage.md](docs/ci-usage.md) for copy-paste workflow snippets.

## Honest limitations

- These checks read the manifest, not the server. They cannot verify that
  auth is enforced, that a resource is really served, or that validation
  exists beyond the schema.
- Description-injection detection is phrase matching. Paraphrased,
  non-English, or obfuscated injections will get through, and legitimate
  imperative descriptions will get flagged.
- A finding is a pointer, not a verdict. Every finding carries remediation
  advice; read it, check the actual server, then decide.
- `path_traversal` takes directory-confinement claims in the description at
  face value and cannot see server-side validation, so a flagged tool may be
  safe behind the scenes. `embedded_secret` cannot tell a real key from a
  placeholder; confirm before rotating.
- Low-severity checks (`no_rate_limit`, `verbose_errors`) are hygiene
  notes. They are noisy on purpose; tune them with a policy file rather
  than ignoring the whole report.

## Roadmap

- Manifest builder that extracts tools/resources/prompts from a live MCP
  server over stdio, so you can audit without hand-writing JSON
- Severity weighting per check in the policy file
- More pair checks (auth tool + anonymous tool on the same server, prompt
  that reads a sensitive resource)
- Larger, community-sourced benchmark manifests

## License

MIT. See LICENSE.
