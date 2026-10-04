"""Flags MCP transports on ports that scanners already probe.

This is a heuristic, and the finding says so. Certain ports show up in
mass scans because they are common development defaults: 3000, 5000,
8000, 8080, 9000, and the MCP Inspector defaults 6274/6277. A server on
one of these is not vulnerable because of the port, but it is easier to
find, and the Ruflo-class incidents started with someone finding the
bridge.

The check reads ``transport.port`` on ``manifest["server"]`` and only
fires for HTTP/SSE transports.

Limitations: purely a discovery heuristic. A production service can live
on 8080 behind proper auth and a firewall and be perfectly fine; the
remediation says exactly that. Disable this check if your fleet
standardizes on one of these ports.
"""

from __future__ import annotations

from ..core import Finding
from .base import Check

#: Ports that show up in mass scans because they are common dev defaults.
#: 6274/6277 are the MCP Inspector defaults; the rest are generic web-dev
#: defaults that MCP bridges keep landing on.
_RISKY_DEFAULT_PORTS = {3000, 5000, 8000, 8080, 9000, 6274, 6277}


class DangerousDefaultPortCheck(Check):
    id = "dangerous_default_port"
    title = "Transport on a commonly scanned default port"
    description = (
        "The MCP transport listens on a port that mass scanners probe by "
        "default (a common dev default or the MCP Inspector default). "
        "Easier to find, not easier to exploit."
    )
    default_severity = "low"
    severity_rationale = (
        "Low because the port alone creates no attack path; it only makes "
        "an exposed server easier to discover. Treat it as a nudge, not an "
        "alarm."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        server = manifest.get("server", {}) or {}
        transport = server.get("transport", {}) or {}
        if transport.get("type") not in ("http", "sse"):
            return findings
        port = transport.get("port")
        try:
            port_num = int(port)
        except (TypeError, ValueError):
            return findings
        if port_num not in _RISKY_DEFAULT_PORTS:
            return findings
        note = (
            " (the MCP Inspector default)"
            if port_num in (6274, 6277)
            else " (a common development default)"
        )
        findings.append(
            self.finding(
                target=f"server:{server.get('name', 'unknown')}",
                title=f"Transport on port {port_num}{note}",
                explanation=(
                    f"The MCP endpoint listens on port {port_num}, which mass "
                    "scanners probe because it is a common default. The port "
                    "itself is not a vulnerability; it just means an exposed "
                    "server gets found faster. This is a heuristic, not a "
                    "verdict."
                ),
                remediation=(
                    "If the server must be network-reachable, prefer an "
                    "uncommon port behind authentication, or keep the default "
                    "port and make sure unauthenticated_exposure and "
                    "exposed_bind are clean. If your fleet standardizes on "
                    "this port, disable this check in the policy file."
                ),
            )
        )
        return findings
