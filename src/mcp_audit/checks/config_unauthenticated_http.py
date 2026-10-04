"""Flags remote MCP servers in client configs with no auth configured.

An HTTP/SSE entry in a client config points the client at a server URL.
If the entry carries no Authorization header (or equivalent), every
request goes out unauthenticated. For a localhost dev server that is
usually fine; for anything across the network it means the tool surface
is open to whoever else can reach that URL, and the client's own calls
carry no identity.

Fires at high for non-loopback URLs without auth headers, medium for
loopback URLs without auth headers (a nudge: localhost today, copied to
a remote host tomorrow). Reads ``manifest["client_servers"]`` from
``mcp_audit.client_config.scan_client_config``; silent on ordinary
server manifests.
"""

from __future__ import annotations

from ..core import Finding
from .base import Check

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _host_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("@")[-1].split(":")[0].lower()


def _has_auth(headers: dict) -> bool:
    lowered = {str(k).lower() for k in headers}
    return "authorization" in lowered or "x-api-key" in lowered


class ConfigUnauthenticatedHttpCheck(Check):
    id = "config_unauthenticated_http"
    title = "Remote MCP server configured without auth"
    description = (
        "An HTTP/SSE client config entry points at a server URL with no "
        "Authorization header. Requests go out unauthenticated."
    )
    default_severity = "high"
    severity_rationale = (
        "High for non-loopback URLs because the calls cross a network with "
        "no identity attached. Medium for localhost, where the risk is a "
        "config copied to a remote host later."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for server in manifest.get("client_servers", []) or []:
            if server.get("transport") not in ("http", "sse"):
                continue
            url = str(server.get("url", "") or "")
            if not url:
                continue
            if _has_auth(server.get("headers", {}) or {}):
                continue
            name = server.get("name", "?")
            source = server.get("source", "config")
            loopback = _host_of(url) in _LOOPBACK_HOSTS
            severity = "medium" if loopback else "high"
            finding = self.finding(
                target=f"server:{name}",
                title=f"'{name}' talks to {url} with no auth header",
                explanation=(
                    f"The {source} config entry '{name}' points at {url} "
                    "and sets no Authorization header, so the client makes "
                    "unauthenticated requests. "
                    + (
                        "Localhost keeps the blast radius small, but this "
                        "exact entry gets copied to remote hosts more often "
                        "than anyone admits."
                        if loopback
                        else "That URL is not localhost, so the tool calls "
                        "cross a network with no identity. If the server "
                        "itself requires no auth either, the bridge is open "
                        "to anyone who can reach it."
                    )
                ),
                remediation=(
                    "Add an Authorization header (or the server's equivalent) "
                    "to the entry, and confirm the server actually enforces "
                    "it with 'mcp-audit live --url ...'."
                ),
                severity=severity,
            )
            finding.severity_rationale = (
                "Medium because localhost keeps the blast radius small, "
                "though the entry tends to get copied to remote hosts."
                if loopback
                else "High because unauthenticated calls cross a real "
                "network with no identity attached."
            )
            findings.append(finding)
        return findings
