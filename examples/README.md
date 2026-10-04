# Examples

Runnable programs and sample manifests. Everything here runs against the
repo checkout (install the package first: `pip install -e .`).

## Manifests

- `vulnerable_manifest.json`: a hand-written manifest that trips the
  scanner on purpose (20 findings: 3 critical, 6 high, 6 medium, 5 low).
  Scan it with `mcp-audit scan examples/vulnerable_manifest.json`.
- `clean_manifest.json`: zero findings, and a reasonable template for how
  to write a manifest.

## audit_fixture_server.py

End-to-end walkthrough: extracts a manifest from the deliberately
vulnerable server source in `fixtures/vulnerable_server/server.py` with
the static extractor, audits it, and prints the report.

```bash
python examples/audit_fixture_server.py
python examples/audit_fixture_server.py --format markdown
python examples/audit_fixture_server.py --format html > report.html
```

The fixture trips all 18 static checks (42 findings: 2 critical, 17 high,
15 medium, 8 low), so this doubles as the nastiest test asset in the
repo. Open the fixture source alongside the output to see each issue in
the code that caused it.

`live_audit_demo.py` is the live-mode counterpart: it starts a
deliberately exposed MCP server in a thread (no auth, shell tool, bound
localhost for safety with a declared 0.0.0.0 deployment) and runs the
real probe against it, so you can watch `unauthenticated_exposure`,
`exposed_bind`, and `network_tool_bridge` fire without deploying
anything.

```bash
python examples/live_audit_demo.py
python examples/live_audit_demo.py --format markdown
```
