"""Flags sensitive resources paired with network-capable tools.

dangerous_combo watches tool pairs; this check watches the resource side.
MCP resources are model-readable without any tool call, so a server that
exposes credentials as a resource and also ships a tool that posts data to
the network has a complete exfiltration path even when no reader tool
exists. One prompt injection can steer the model to read the resource and
hand it to the sender tool.

This reuses the sensitive-path patterns from sensitive_resource and the
network-capability heuristic from dangerous_combo. Like both, it reads the
manifest only: it cannot confirm the resource is actually served or that
the sender tool is reachable, so a hit means "trace this path by hand",
not "this server is leaking".
"""

from __future__ import annotations

from ..core import Finding
from .base import Check
from .dangerous_combo import _SEND
from .sensitive_resource import _BROAD_SYSTEM_PATHS, _CRITICAL_PATHS


class ExfiltrationPathCheck(Check):
    id = "exfiltration_path"
    title = "Sensitive resource plus network sender"
    description = (
        "A resource exposing credentials or keys on a server that also has a "
        "tool able to send data to the network: a complete exfiltration path "
        "with no reader tool needed."
    )
    default_severity = "high"
    severity_rationale = (
        "High because the path is complete: the resource is model-readable with "
        "no tool call needed, and the sender needs only one steered call to move "
        "the secret off the host."
    )

    def _sensitive_resources(self, manifest: dict) -> list[str]:
        names = []
        for resource in self.resources(manifest):
            uri = resource.get("uri", "") or ""
            name = resource.get("name", uri)
            if _CRITICAL_PATHS.search(uri) or _BROAD_SYSTEM_PATHS.search(uri):
                names.append(name)
        return names

    def _senders(self, manifest: dict) -> list[str]:
        return [
            t.get("name", "?")
            for t in self.tools(manifest)
            if _SEND.search(f"{t.get('name', '')} {t.get('description', '')}")
        ]

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        sensitives = self._sensitive_resources(manifest)
        senders = self._senders(manifest)
        if not sensitives or not senders:
            return findings
        for resource_name in sensitives:
            pair = f"{resource_name} + {senders[0]}"
            findings.append(
                self.finding(
                    target=f"server:{pair}",
                    title=(
                        f"Exfiltration path: resource '{resource_name}' holds "
                        f"sensitive data, tool '{senders[0]}' reaches the network"
                    ),
                    explanation=(
                        f"The resource '{resource_name}' looks like it exposes "
                        f"credentials, keys, or system files, and the tool "
                        f"'{senders[0]}' can send data to the network. Resources "
                        f"are model-readable without a tool call, so a steered "
                        f"model can read the resource and hand it to the sender "
                        f"in one session."
                    ),
                    remediation=(
                        "Break the chain: stop exposing the sensitive resource, "
                        "restrict the sender to allowlisted destinations, or "
                        "require human approval when sensitive resources and "
                        "network tools are used together."
                    ),
                )
            )
        return findings
