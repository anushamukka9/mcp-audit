"""Audit the bundled vulnerable-server fixture end to end.

This is the full mcp-audit workflow on one file:

1. Extract a manifest from fixtures/vulnerable_server/server.py with the
   static extractor (no server execution, just AST parsing).
2. Merge the fixture's hand-declared resources and prompt templates, which
   the --py extractor does not pull out of source.
3. Audit the manifest and print the report.

The fixture is vulnerable on purpose, so expect a failing policy and a
non-zero exit code. That is the point: run it, read the findings, then
open the fixture source and see each issue in the code that caused it.

Usage:
    python examples/audit_fixture_server.py [--format table|json|markdown|html]
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from extract_manifest import extract_py  # noqa: E402

from mcp_audit import AuditPolicy, audit_server  # noqa: E402
from mcp_audit.report import format_report  # noqa: E402

FIXTURE = REPO / "fixtures" / "vulnerable_server" / "server.py"


def _static_literal(name: str):
    """Read a module-level literal from the fixture without importing it."""
    tree = ast.parse(FIXTURE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ):
            return ast.literal_eval(node.value)
    raise KeyError(f"{name} not found in {FIXTURE}")


def build_manifest() -> dict:
    """Extract tools/prompts from the fixture source and merge the rest."""
    src = FIXTURE.read_text(encoding="utf-8")
    tools, _resources, prompts = extract_py(src)
    templates = _static_literal("PROMPT_TEMPLATES")
    for prompt in prompts:
        prompt["template"] = templates.get(prompt["name"], "")
    return {
        "server": {"name": "fixture-vulnerable-server", "version": "0.1.0"},
        "tools": tools,
        "resources": _static_literal("RESOURCES"),
        "prompts": prompts,
    }


def main(argv: list[str] | None = None) -> int:
    fmt = "table"
    args = list(argv or [])
    if args and args[0] == "--format" and len(args) > 1:
        fmt = args[1]
    manifest = build_manifest()
    policy = AuditPolicy(fail_on="high")
    report = audit_server(manifest, policy=policy)
    print(format_report(report, fmt))
    print()
    print(f"policy: fail_on=high -> {'PASS' if policy.passes(report) else 'FAIL'}")
    return 0 if policy.passes(report) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
