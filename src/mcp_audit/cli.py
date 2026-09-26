"""Command-line interface: mcp-audit scan manifest.json"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, audit_server, default_checks
from .core import AuditReport
from .policy import AuditPolicy


def _load_manifest(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")
    return data


def _load_policy(path: str | None, fail_on: str | None) -> AuditPolicy:
    if path:
        with open(path, encoding="utf-8") as fh:
            policy = AuditPolicy.from_dict(json.load(fh))
    else:
        policy = AuditPolicy()
    if fail_on:
        policy.fail_on = fail_on
    return policy


def format_table(report: AuditReport) -> str:
    lines = [f"mcp-audit: {report.manifest_name} - {len(report.findings)} finding(s)"]
    counts = report.counts()
    lines.append("severity: " + ", ".join(f"{sev}={counts[sev]}" for sev in counts))
    lines.append("")
    if not report.findings:
        lines.append("No findings. Nice manifest.")
        return "\n".join(lines)
    for finding in report.findings:
        lines.append(f"[{finding.severity.upper():8}] {finding.target}")
        lines.append(f"           {finding.title} ({finding.check_id})")
    return "\n".join(lines)


def format_markdown(report: AuditReport) -> str:
    lines = [f"# mcp-audit: {report.manifest_name}", ""]
    counts = report.counts()
    lines.append(" | ".join(f"{sev}: {counts[sev]}" for sev in counts))
    lines.append("")
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines)
    for finding in report.findings:
        lines.append(f"## [{finding.severity}] {finding.title}")
        lines.append(f"Target: `{finding.target}` - check: `{finding.check_id}`")
        lines.append("")
        lines.append(finding.explanation)
        lines.append("")
        lines.append(f"**Fix:** {finding.remediation}")
        lines.append("")
    return "\n".join(lines)


_SARIF_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _sarif_level(severity: str) -> str:
    return _SARIF_LEVELS[severity]


def format_sarif(report: AuditReport) -> str:
    """Minimal SARIF 2.1.0 output for CI code-scanning ingestion."""
    rules = [
        {
            "id": check.id,
            "name": check.title,
            "shortDescription": {"text": check.description},
        }
        for check in default_checks()
    ]
    results = [
        {
            "ruleId": f.check_id,
            "level": _sarif_level(f.severity),
            "message": {"text": f"{f.title}: {f.explanation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.target}}}],
        }
        for f in report.findings
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "mcp-audit", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        manifest = _load_manifest(args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read manifest: {exc}", file=sys.stderr)
        return 2
    try:
        policy = _load_policy(args.config, args.fail_on)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read policy config: {exc}", file=sys.stderr)
        return 2

    report = audit_server(manifest, policy=policy)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    elif args.format == "sarif":
        print(format_sarif(report))
    elif args.format == "markdown":
        print(format_markdown(report))
    else:
        print(format_table(report))

    if not policy.passes(report):
        print(
            f"\nFAILED: findings at or above '{policy.fail_on}' severity.",
            file=sys.stderr,
        )
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Audit an MCP server manifest for security issues.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Audit a manifest file.")
    scan.add_argument("manifest", help="Path to the server manifest JSON file.")
    scan.add_argument(
        "--format",
        choices=["table", "json", "sarif", "markdown"],
        default="table",
        help="Output format (default: table).",
    )
    scan.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "never"],
        default=None,
        help="Exit 1 if any finding meets this severity (default: high).",
    )
    scan.add_argument(
        "--config",
        default=None,
        help="Path to a JSON policy file (fail_on, disabled_checks, allowlist).",
    )
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
