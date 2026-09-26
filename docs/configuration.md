# Configuration

mcp-audit works out of the box with `fail_on: high` and every check enabled.
When the defaults are too strict (or too loud) for your server, write a
policy file and pass it with `--config`.

## Policy file format

```json
{
  "fail_on": "high",
  "disabled_checks": ["no_rate_limit"],
  "allowlist": {
    "weak_input_schema": ["tool:search_docs"]
  }
}
```

- **fail_on**: `critical`, `high`, `medium`, `low`, or `never`. The CLI exits
  1 when any surviving finding meets this severity. Default: `high`.
- **disabled_checks**: check ids to skip entirely. Use this for checks that
  do not apply to your server, not to silence findings you have not read.
- **allowlist**: per-check lists of targets to skip, as `tool:name`,
  `resource:name`, `prompt:name`, or `server:a + b`. Use this for findings
  you have reviewed and accepted.

## Same knobs in Python

```python
from mcp_audit import AuditPolicy, audit_server

policy = AuditPolicy(
    fail_on="medium",
    disabled_checks=["verbose_errors"],
    allowlist={"no_rate_limit": ["tool:search_docs"]},
)
report = audit_server(manifest, policy=policy)
print("passed:", policy.passes(report))
```

Findings filtered by the policy never appear in `report.findings`, so
downstream formats (JSON, SARIF, markdown) only contain what survived.

## Choosing fail_on

- `high` (default): blocks on anything an attacker can directly use.
- `medium`: also blocks on hygiene issues like missing auth annotations.
  Good for servers you ship to other people.
- `low`: blocks on everything, including rate-limit and error-verbosity
  notes. Expect to maintain an allowlist.
- `never`: report only. Useful for a first audit of a server you inherited.
