"""Flags MCP client configs that pull server code from the network.

A stdio entry like ``{"command": "npx", "args": ["-y", "some-server"]}``
downloads and runs whatever ``some-server`` currently resolves to, every
time the client starts. That is convenient and it is also the
slopsquatting shape: package names get hallucinated, typosquatted, or
taken over, and the client runs the result with the user's privileges.

This check fires when the launcher is a package runner (npx, uvx, bunx,
dlx, pnpm dlx) and the package spec is remote (not a file: URL, not a
local path) and unpinned (no ``@version``). Pinned versions still
download code, but at least the bytes are stable; unpinned ``-y`` runs
are the risky end.

These checks read ``manifest["client_servers"]``, which
``mcp_audit.client_config.scan_client_config`` builds from Claude
Desktop, Cursor, or Claude Code config files. They stay silent on
ordinary server manifests.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_PACKAGE_RUNNERS = {"npx", "uvx", "bunx", "dlx", "pnpm"}
_LOCAL_PREFIXES = ("file:", "./", "../", "/", "~")


def _package_arg(args: list[str]) -> str | None:
    """First arg that looks like a package spec, skipping flags."""
    for arg in args:
        if arg.startswith("-"):
            continue
        return arg
    return None


class ConfigRemotePackageCheck(Check):
    id = "config_remote_package"
    title = "Client config runs a remote package on every start"
    description = (
        "A stdio MCP server entry downloads and executes a remote package "
        "(npx/uvx/bunx) without a pinned version. Every client start runs "
        "whatever the registry serves today."
    )
    default_severity = "high"
    severity_rationale = (
        "High because the client executes third-party code with the user's "
        "privileges on every launch, and an unpinned spec means the code "
        "can change under you. Typosquats and package takeovers are a "
        "realistic path, not a theoretical one."
    )

    def _servers(self, manifest: dict) -> list[dict]:
        return manifest.get("client_servers", []) or []

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for server in self._servers(manifest):
            if server.get("transport") != "stdio":
                continue
            command = str(server.get("command", "") or "")
            base = command.rsplit("/", 1)[-1].lower()
            args = [str(a) for a in (server.get("args") or [])]
            if base not in _PACKAGE_RUNNERS and not (base == "pnpm" and args[:1] == ["dlx"]):
                continue
            pkg = _package_arg(args[1:] if base == "pnpm" else args)
            if not pkg:
                continue
            if pkg.startswith(_LOCAL_PREFIXES):
                continue
            if re.match(r"^@[a-z0-9-~][a-z0-9-._~]*/", pkg):
                pkg_name = pkg  # scoped package, check the version pin below
            else:
                pkg_name = pkg
            if "@" in pkg_name.split("/", 1)[-1]:
                continue  # pinned to a version or tag
            name = server.get("name", "?")
            source = server.get("source", "config")
            findings.append(
                self.finding(
                    target=f"server:{name}",
                    title=f"'{name}' runs unpinned remote package '{pkg}'",
                    explanation=(
                        f"The {source} config entry '{name}' launches "
                        f"'{command} {' '.join(args)}', which downloads and "
                        f"runs the '{pkg}' package from the registry on every "
                        "client start, with no version pin. If that name gets "
                        "typosquatted, hallucinated into existence, or taken "
                        "over, the client runs attacker code with your user's "
                        "privileges."
                    ),
                    remediation=(
                        f"Pin the package to an exact version ('{pkg}@1.2.3'), "
                        "verify the name against the publisher you trust, and "
                        "prefer a locally installed copy for servers you run "
                        "daily."
                    ),
                )
            )
        return findings
