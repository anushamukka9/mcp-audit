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
| `approval_bypass` | high | Descriptions that tell the agent no human confirmation is needed ("auto-approve", "no need to ask") |
| `credential_request` | high | Input schemas asking the caller to supply passwords, API keys, or tokens |

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

Results on the bundled set (18 manifests, 28 check activations):

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
| approval_bypass | 1 | 1.00 | 1.00 | 1.00 |
| credential_request | 1 | 1.00 | 1.00 | 1.00 |

Take these numbers for what they are: a smoke test proving the patterns
fire on the obvious cases, not a security certification. The set is small
and hand-written. Real servers are more creative than any labeled set. If
you evaluate against your own manifests, please contribute the cases back.

## Findings on real public MCP servers

Labeled benchmarks are a smoke test. To see what the checks do in the
wild, I extracted tool, resource, and prompt definitions from the source
of four reference servers in
[modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers)
at commit `f46d957` (2026-09-22) and scanned them with the default policy.
Manifests were built with a static source extractor
(`scripts/extract_manifest.py`), so the whole thing is reproducible.

| server | tools scanned | critical | high | medium | low |
|---|---|---|---|---|---|
| filesystem | 14 | 0 | 2 | 15 | 14 |
| memory | 9 | 0 | 0 | 5 | 9 |
| fetch | 1 | 0 | 1 | 0 | 1 |
| git | 12 | 0 | 0 | 1 | 12 |

What the findings actually mean, server by server:

**filesystem** (31 findings). The two highs are `broad_tool` on
`write_file` and `create_directory`: they write to caller-supplied paths,
which is the tool's entire job, and the server confines them to allowed
directories via `validatePath` in `path-validation.ts`. By design,
flagged so you confirm the confinement. The mediums split into
`missing_auth` on the four mutating tools (they carry `readOnlyHint` but
no auth annotation, so clients cannot tell if calls are access
controlled) and `weak_input_schema` on the bare-string `path` parameters
(schema-level validation is absent; the server validates behind the
scenes, which the check cannot see). The 14 lows are `no_rate_limit`
hygiene notes.

**memory** (14 findings). Five `missing_auth` mediums on the mutating
knowledge-graph tools (`create_entities`, `create_relations`,
`delete_entities`, `delete_observations`, `delete_relations`), nine
`no_rate_limit` lows. Otherwise clean: no injection, no broad tools, no
secrets. Note that `add_observations` escaped `missing_auth` for the same
reason as git's commit tools below: "add" is not in the mutating-word
list either.

**fetch** (2 findings). One `broad_tool` high: it fetches arbitrary URLs
with no allowlist, which is the tool's stated purpose (it honors
robots.txt server-side). One `no_rate_limit` low. The `url` parameter
carries `AnyUrl` typing, so `weak_input_schema` correctly stays quiet.

**git** (13 findings). Twelve `no_rate_limit` lows and one
`missing_auth` medium on `git_reset` (it sets `destructiveHint` with no
auth annotation). Worth noting: `git_commit`, `git_add`, and
`git_checkout` did not flag because the mutating-word list does not
include verbs like "commit", "stage", or "checkout". That is a real
coverage gap in `missing_auth`, documented here instead of hidden.

Two things did not fire anywhere: `description_injection`,
`embedded_secret`, `tool_impersonation`, `dangerous_combo`,
`sensitive_resource`, `verbose_errors`, and `prompt_template_injection`
came back clean on all four servers.

The most useful result was a bug in mcp-audit itself. The first scan
flagged `path_traversal` on `read_text_file`, `read_media_file`, and
`directory_tree`, even though every one of those descriptions ends with
"Only works within allowed directories" and the server genuinely
validates paths. Root cause: the guard pattern recognized "directory"
but not "directories". Fixed in 0.2.1 (plural handling plus a regression
test); those three findings clear after the fix. This is exactly why you
run your own tool against the real world.

Read this section the way the tool intends: static, lint-level
observations, not CVEs and not vulnerability disclosures. Several
findings describe capabilities that are intentional. The annotation
checks (`missing_auth`, `no_rate_limit`) are noisy across the ecosystem
because servers rarely populate that metadata. A finding is a pointer;
check the server, then decide.

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
- `approval_bypass` is phrase matching and will flag harmless read-only
  tools whose authors wrote "no confirmation needed" as a courtesy.
  `credential_request` skips tools that present themselves as
  authentication and does not inspect nested schemas; a hit means "read
  this tool", not "this tool is phishing".
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
