"""Flags an MCP server bound to all network interfaces.

Binding to 0.0.0.0 (or ::) means every machine that can route to the host
can reach the MCP endpoint. On its own that is a deployment choice, but
combined with an unauthenticated transport it is the CVE-2026-59726
pattern: a tool bridge the whole network can drive. Even with auth, a
wide bind multiplies the value of every other finding.

The check reads ``transport.bind`` on ``manifest["server"]``. The live
audit fills it from the ``--bind`` flag (a probe cannot see how the
server binds from the outside, so this value is always declared; the
finding says so).

Limitations: a declared bind is only as honest as the person who passed
``--bind``. When no bind is declared the check stays silent rather than
guessing.
"""

from __future__ import annotations

from ..core import Finding
from .base import Check

_WIDE_BINDS = {"0.0.0.0", "::", "[::]"}


class ExposedBindCheck(Check):
    id = "exposed_bind"
    title = "Server bound to all network interfaces"
    description = (
        "The MCP transport is bound to 0.0.0.0 (or the IPv6 equivalent), "
        "so the endpoint is reachable from anywhere that can route to the "
        "host, not just localhost."
    )
    default_severity = "high"
    severity_rationale = (
        "High because a wide bind turns every other weakness into a remote "
        "one. It is not an exploit by itself, which is why it is not "
        "critical, but it is the multiplier behind the worst MCP incidents."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        server = manifest.get("server", {}) or {}
        transport = server.get("transport", {}) or {}
        if transport.get("type") not in ("http", "sse"):
            return findings
        bind = str(transport.get("bind", "") or "").strip()
        if bind not in _WIDE_BINDS:
            return findings
        port = transport.get("port", "?")
        findings.append(
            self.finding(
                target=f"server:{server.get('name', 'unknown')}",
                title=f"Transport bound to {bind} on port {port}",
                explanation=(
                    f"The server binds {bind}:{port}, so its MCP endpoint "
                    "accepts connections from the whole network, not just this "
                    "machine. The Ruflo bridge (CVE-2026-59726) was exposed "
                    "exactly this way: bound wide open with no auth in front. "
                    "Note this value is declared (via --bind), not measured; a "
                    "probe cannot see a server's bind address from outside."
                ),
                remediation=(
                    "Bind to 127.0.0.1 unless remote clients genuinely need "
                    "direct access, and put those behind a reverse proxy with "
                    "authentication. If remote access is intended, make sure "
                    "the unauthenticated_exposure check is clean first."
                ),
            )
        )
        return findings
