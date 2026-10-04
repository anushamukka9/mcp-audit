"""Flags privileged tools behind a network-reachable MCP transport.

This is the "network-reachable tool bridge" shape: the transport is not
loopback-only, and the tool surface includes shell execution or arbitrary
file writes. A remote caller who reaches the bridge gets the agent's
hands, not just its answers. The Ruflo bridge (CVE-2026-59726) exposed a
full tool surface this way.

Network reachability is decided from the ``transport`` block on
``manifest["server"]``: reachable when the declared bind is wide
(0.0.0.0/::) or, if no bind is declared, when the URL host is not a
loopback address. A loopback-only bind means "not reachable", even if
other checks fired.

"Privileged" here means shell/command execution or arbitrary file
writes, using the same patterns as the broad_tool check. Network fetch
tools are deliberately excluded: the bridge itself is the network part,
so flagging fetch tools too would double-count.

Limitations: reachability is derived from declared values, which are
only as honest as the manifest. The check cannot see firewall rules,
security groups, or VPNs that might fence the port off.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
_WIDE_BINDS = {"0.0.0.0", "::", "[::]"}

_SHELL = re.compile(
    r"\b(sh|bash|zsh|powershell|cmd\.exe|shell|subprocess|os\.system|popen)\b",
    re.I,
)
_EXEC_PARAM = re.compile(r"\b(command|cmd|script|argv)\b", re.I)
_WRITE = re.compile(
    r"\b(write|save|create|delete|remove)\b.{0,30}\b(file|files|path|directory)\b"
    r"|\b(file|path)\b.{0,20}\b(write|save|delete|remove)\b",
    re.I,
)


def _is_privileged(tool: dict) -> str | None:
    """Return 'shell' or 'write' if the tool looks privileged, else None."""
    name = tool.get("name", "") or ""
    desc = tool.get("description", "") or ""
    schema = tool.get("inputSchema", {}) or {}
    params = schema.get("properties", {}) or {}
    text = f"{name} {desc}"
    blob = f"{text} {' '.join(params)}"
    if _SHELL.search(text) and _EXEC_PARAM.search(blob):
        return "shell"
    if _SHELL.search(name):
        return "shell"
    if _WRITE.search(text):
        return "write"
    return None


def _network_reachable(transport: dict) -> bool:
    bind = str(transport.get("bind", "") or "").strip().lower()
    if bind:
        return bind in _WIDE_BINDS
    host = str(transport.get("host", "") or "").strip().lower()
    if not host:
        url = str(transport.get("url", "") or "")
        match = re.search(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#@]+)", url)
        host = (match.group(1) if match else "").lower()
    return bool(host) and host not in _LOOPBACK_HOSTS


class NetworkToolBridgeCheck(Check):
    id = "network_tool_bridge"
    title = "Privileged tools behind a network-reachable transport"
    description = (
        "The MCP transport is reachable beyond localhost and the tool "
        "surface includes shell execution or arbitrary file writes. A "
        "remote caller gets the agent's hands."
    )
    default_severity = "high"
    severity_rationale = (
        "High because it pairs remote reachability with the two tool "
        "shapes that turn access into control. It stops short of critical "
        "because the check cannot see whether auth or a firewall stands in "
        "front."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        server = manifest.get("server", {}) or {}
        transport = server.get("transport", {}) or {}
        if transport.get("type") not in ("http", "sse"):
            return findings
        if not _network_reachable(transport):
            return findings
        privileged = []
        for tool in self.tools(manifest):
            kind = _is_privileged(tool)
            if kind:
                privileged.append((tool.get("name", "?"), kind))
        if not privileged:
            return findings
        names = ", ".join(f"{name} ({kind})" for name, kind in privileged)
        findings.append(
            self.finding(
                target=f"server:{server.get('name', 'unknown')}",
                title=(f"{len(privileged)} privileged tool(s) on a network-reachable bridge"),
                explanation=(
                    "The transport is reachable beyond localhost and these "
                    f"tools look privileged: {names}. Whoever reaches the "
                    "bridge can run them. This is the shape that made the "
                    "Ruflo bridge (CVE-2026-59726) a CVSS 10.0: not a bug in "
                    "any one tool, but a full privileged surface with no "
                    "network boundary."
                ),
                remediation=(
                    "Either fence the network (bind 127.0.0.1, firewall the "
                    "port, require auth) or shrink the tool surface (drop "
                    "shell/file-write tools, or gate them behind approval). "
                    "One of the two has to give; ideally both."
                ),
            )
        )
        return findings
