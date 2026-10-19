"""Command-line interface: mcp-audit scan manifest.json"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, audit_server
from .checks import default_checks
from .checks.known_vulnerable_package import KnownVulnerablePackageCheck
from .client_config import scan_client_config, scan_discovered_configs
from .cve_feed import load_feed
from .live import (
    LiveAuditError,
    LiveTarget,
    live_audit,
    parse_command,
    parse_env,
    parse_headers,
)
from .policy import AuditPolicy
from .report import _FORMATS, format_report


def _load_manifest(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")
    return data


def _load_checks(cve_feed_path: str | None) -> list | None:
    """Default checks, or defaults with the CVE check fed from a file.

    Returns None when no --cve-feed was passed, which audit_server reads
    as "use the defaults" (bundled feed snapshot included).
    """
    if not cve_feed_path:
        return None
    feed = load_feed(cve_feed_path)
    checks = [c for c in default_checks() if c.id != "known_vulnerable_package"]
    checks.append(KnownVulnerablePackageCheck(feed))
    return checks


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
    try:
        checks = _load_checks(args.cve_feed)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read CVE feed: {exc}", file=sys.stderr)
        return 2

    report = audit_server(manifest, checks=checks, policy=policy)

    print(format_report(report, args.format))

    if not policy.passes(report):
        print(
            f"\nFAILED: findings at or above '{policy.fail_on}' severity.",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_live(args: argparse.Namespace) -> int:
    try:
        policy = _load_policy(args.config, args.fail_on)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read policy config: {exc}", file=sys.stderr)
        return 2
    try:
        checks = _load_checks(args.cve_feed)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read CVE feed: {exc}", file=sys.stderr)
        return 2
    try:
        headers = parse_headers(args.header)
        env = parse_env(args.env)
        target = LiveTarget(
            url=args.url,
            command=parse_command(args.command) if args.command else [],
            headers=headers,
            env=env,
            bind=args.bind,
            timeout=args.timeout,
        )
        report = live_audit(target, checks=checks, policy=policy)
    except LiveAuditError as exc:
        print(f"error: live audit failed: {exc}", file=sys.stderr)
        return 2

    print(format_report(report, args.format))

    if not policy.passes(report):
        print(
            f"\nFAILED: findings at or above '{policy.fail_on}' severity.",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_scan_config(args: argparse.Namespace) -> int:
    try:
        policy = _load_policy(args.config, args.fail_on)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read policy config: {exc}", file=sys.stderr)
        return 2

    try:
        config_checks = _load_checks(args.cve_feed)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read CVE feed: {exc}", file=sys.stderr)
        return 2

    if args.path:
        try:
            report = scan_client_config(args.path, checks=config_checks, policy=policy)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: cannot read {args.path}: {exc}", file=sys.stderr)
            return 2
        jobs = [("config", args.path, report)]
    else:
        try:
            jobs = scan_discovered_configs(checks=config_checks, policy=policy)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: cannot read a discovered config: {exc}", file=sys.stderr)
            return 2
        if not jobs:
            print("no MCP client configs found in the usual locations.")
            print("Pass --path to scan a specific file.")
            return 0

    failed = False
    for source, path, report in jobs:
        print(f"--- {source}: {path} ---")
        print(format_report(report, args.format))
        print()
        if not policy.passes(report):
            failed = True
    if failed:
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
    scan.add_argument(
        "--cve-feed",
        default=None,
        help="Path to a CVE feed JSON file for the known_vulnerable_package "
        "check. Defaults to the bundled snapshot; the scan stays offline "
        "either way.",
    )
    scan.set_defaults(func=cmd_scan)

    live = sub.add_parser(
        "live",
        help="Audit a running MCP server (HTTP/SSE or stdio).",
        description=(
            "Connect to a running MCP server, enumerate its tools, resources, "
            "and prompts over the live protocol, and audit what it actually "
            "exposes. The auth probe is real: an unauthenticated tools/list "
            "is attempted first."
        ),
    )
    target_group = live.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--url",
        default=None,
        help="HTTP(S) URL of the MCP endpoint (streamable HTTP or SSE).",
    )
    target_group.add_argument(
        "--command",
        default=None,
        help="Shell-style command launching the server over stdio, e.g. 'python server.py'.",
    )
    live.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'Name: Value'",
        help="HTTP header to send (repeatable). Used after the "
        "unauthenticated probe when the server requires auth.",
    )
    live.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Environment variable for a --command server (repeatable).",
    )
    live.add_argument(
        "--bind",
        default=None,
        help="How the server binds (e.g. 0.0.0.0 or 127.0.0.1). Declared, "
        "not measured: a probe cannot see a bind address from outside.",
    )
    live.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Seconds to wait for server responses (default: 10).",
    )
    live.add_argument(
        "--format",
        choices=list(_FORMATS),
        default="table",
        help="Output format (default: table).",
    )
    live.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "never"],
        default=None,
        help="Exit 1 if any finding meets this severity (default: high).",
    )
    live.add_argument(
        "--config",
        default=None,
        help="Path to a JSON policy file (fail_on, disabled_checks, allowlist).",
    )
    live.add_argument(
        "--cve-feed",
        default=None,
        help="Path to a CVE feed JSON file for the known_vulnerable_package "
        "check. Defaults to the bundled snapshot; the scan stays offline "
        "either way.",
    )
    live.set_defaults(func=cmd_live)

    scfg = sub.add_parser(
        "scan-config",
        help="Scan MCP client configs (Claude Desktop, Cursor, Claude Code).",
        description=(
            "Read MCP client config files and flag risky server entries: "
            "unpinned remote packages, plaintext secrets, unauthenticated "
            "HTTP servers, plaintext HTTP off localhost, and piped "
            "download-to-shell commands."
        ),
    )
    scfg.add_argument(
        "--path",
        default=None,
        help="Config file to scan. Defaults to auto-discovering the usual "
        "Claude Desktop / Cursor / Claude Code locations.",
    )
    scfg.add_argument(
        "--format",
        choices=list(_FORMATS),
        default="table",
        help="Output format (default: table).",
    )
    scfg.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "never"],
        default=None,
        help="Exit 1 if any finding meets this severity (default: high).",
    )
    scfg.add_argument(
        "--config",
        default=None,
        help="Path to a JSON policy file (fail_on, disabled_checks, allowlist).",
    )
    scfg.add_argument(
        "--cve-feed",
        default=None,
        help="Path to a CVE feed JSON file for the known_vulnerable_package "
        "check. Defaults to the bundled snapshot; the scan stays offline "
        "either way.",
    )
    scfg.set_defaults(func=cmd_scan_config)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
