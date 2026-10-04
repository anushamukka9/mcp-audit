"""Flags an HTTP/SSE transport that answers without authentication.

This is the Ruflo failure mode (CVE-2026-59726): an MCP bridge bound to
the network, reachable by anyone, with no auth in front of the tool
surface. Whoever can reach it can call every tool the agent can call.

The check reads the ``transport`` block on ``manifest["server"]``:

    "transport": {
        "type": "http",
        "url": "http://0.0.0.0:8080/mcp",
        "auth_required": false,
        "probed": true
    }

``mcp-audit live`` fills this in from a real probe: it sends an
unauthenticated ``tools/list`` first, so ``auth_required: false`` with
``probed: true`` means the exposure was measured, not guessed. A static
manifest can declare the same block; then the finding is honest about
being declared rather than measured.

Limitations: the probe only tests the methods it calls (initialize and
tools/list). A server that demands auth on tools/call but not on
tools/list would pass the probe and still be exposed where it matters.
"""

from __future__ import annotations

from ..core import Finding
from .base import Check

_NETWORK_TYPES = ("http", "sse")


class UnauthenticatedExposureCheck(Check):
    id = "unauthenticated_exposure"
    title = "Network transport answers without authentication"
    description = (
        "The MCP server is reachable over HTTP/SSE and answered an "
        "unauthenticated request. Anyone who can reach the port gets the "
        "agent's full tool surface."
    )
    default_severity = "critical"
    severity_rationale = (
        "Critical when a live probe proved the exposure, because an "
        "unauthenticated tool bridge is remote code execution by "
        "invitation. High when only declared in a static manifest, "
        "because the setting is one deploy away from being true."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        server = manifest.get("server", {}) or {}
        transport = server.get("transport", {}) or {}
        if transport.get("type") not in _NETWORK_TYPES:
            return findings
        if transport.get("auth_required", True):
            return findings
        probed = bool(transport.get("probed"))
        severity = "critical" if probed else "high"
        url = transport.get("url", "the server URL")
        if probed:
            explanation = (
                f"A live probe sent an unauthenticated tools/list request to {url} "
                "and got a working answer. No credentials, no token, no handshake. "
                "This is the exact shape of the Ruflo incident (CVE-2026-59726): an "
                "MCP bridge exposed to the network with nothing in front of it."
            )
        else:
            explanation = (
                f"The manifest declares that {url} requires no authentication "
                "(auth_required: false, not measured by a probe). If the deployed "
                "server matches this manifest, anyone who can reach the port can "
                "call every tool."
            )
        finding = self.finding(
            target=f"server:{server.get('name', 'unknown')}",
            title="MCP transport is exposed without authentication",
            explanation=explanation,
            remediation=(
                "Put authentication in front of the MCP endpoint (bearer token, "
                "mTLS, or your existing API gateway auth) and re-run "
                "'mcp-audit live' to confirm the probe now gets a 401. If the "
                "server is meant to be local-only, bind it to 127.0.0.1 as well."
            ),
            severity=severity,
        )
        finding.severity_rationale = (
            "Critical because the probe proved it: an unauthenticated caller got "
            "a working tools/list response, which is the Ruflo failure mode."
            if probed
            else "High because the manifest declares no auth on a network "
            "transport; the setting is one deploy away from being the Ruflo "
            "failure mode."
        )
        findings.append(finding)
        return findings
