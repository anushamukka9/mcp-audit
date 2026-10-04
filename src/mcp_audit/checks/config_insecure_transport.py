"""Flags plaintext-HTTP MCP URLs pointing off localhost.

MCP over HTTP without TLS means tool names, parameters, and results
travel the network in the clear. Against localhost that is normal dev
practice; against any other host it is credential and data exposure
waiting for a packet capture.

Reads ``manifest["client_servers"]`` from
``mcp_audit.client_config.scan_client_config``; silent on ordinary
server manifests. Does not flag https:// URLs or http://localhost.
"""

from __future__ import annotations

from ..core import Finding
from .base import Check

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _host_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("@")[-1].split(":")[0].lower()


class ConfigInsecureTransportCheck(Check):
    id = "config_insecure_transport"
    title = "Plaintext HTTP to a non-localhost MCP server"
    description = (
        "A client config entry uses http:// (not https://) for a server "
        "that is not localhost. Tool traffic crosses the network in the "
        "clear."
    )
    default_severity = "high"
    severity_rationale = (
        "High because everything the agent sends and receives, including "
        "any credentials in parameters, is readable to anyone on the path. "
        "Localhost is exempt because the traffic never leaves the machine."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for server in manifest.get("client_servers", []) or []:
            if server.get("transport") not in ("http", "sse"):
                continue
            url = str(server.get("url", "") or "")
            if not url.lower().startswith("http://"):
                continue
            if _host_of(url) in _LOOPBACK_HOSTS:
                continue
            name = server.get("name", "?")
            source = server.get("source", "config")
            findings.append(
                self.finding(
                    target=f"server:{name}",
                    title=f"'{name}' uses plaintext HTTP to {_host_of(url)}",
                    explanation=(
                        f"The {source} config entry '{name}' points at {url} "
                        "over plaintext HTTP, and the host is not localhost. "
                        "Tool calls, parameters, and results cross the "
                        "network unencrypted, so anything sensitive the "
                        "agent touches is visible to anyone on the path."
                    ),
                    remediation=(
                        "Switch the entry to https:// (and make sure the "
                        "server actually serves TLS), or tunnel it through "
                        "SSH or your VPN if the server cannot do TLS itself."
                    ),
                )
            )
        return findings
