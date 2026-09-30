"""Command-line interface: mcp-audit scan manifest.json"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, audit_server
from .policy import AuditPolicy
from .report import _FORMATS, format_report


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

    print(format_report(report, args.format))

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
        choices=list(_FORMATS),
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
