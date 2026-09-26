"""Flags resources that expose sensitive paths.

MCP resources are directly readable by the model, so a resource pointing at
/etc/passwd, an SSH key, or a .env file hands credentials to anything that
can steer the model toward reading it. This check matches resource URIs
against sensitive-path patterns. It reads the manifest only: it cannot tell
whether the server actually serves the file or whether access is restricted
behind the scenes, so confirm before panicking.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_CRITICAL_PATHS = re.compile(
    r"(/etc/(passwd|shadow|sudoers)|/\.ssh/|id_rsa|id_ed25519|\.pem$|\.key$|"
    r"\.env$|credentials|secrets\.json|\.aws/credentials)",
    re.I,
)
_BROAD_SYSTEM_PATHS = re.compile(r"file://(/etc/|/root/|/var/|/private/|C:/Windows/)", re.I)


class SensitiveResourceCheck(Check):
    id = "sensitive_resource"
    title = "Resource exposes a sensitive path"
    description = (
        "Resources are model-readable. URIs pointing at credentials, keys, or "
        "system files put secrets one tool call away."
    )
    default_severity = "high"

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for resource in self.resources(manifest):
            uri = resource.get("uri", "")
            name = resource.get("name", uri)
            if not uri:
                continue
            if _CRITICAL_PATHS.search(uri):
                findings.append(
                    self.finding(
                        target=f"resource:{name}",
                        title=f"Resource '{name}' points at credentials or keys",
                        explanation=(
                            f"The resource URI ({uri}) looks like it exposes "
                            f"credentials, private keys, or secrets. Anything that "
                            f"can get the model to read this resource learns the "
                            f"secret."
                        ),
                        remediation=(
                            "Remove the resource or point it at non-sensitive data. "
                            "If the server genuinely needs the secret, keep it "
                            "server-side and never expose it as a resource."
                        ),
                        severity="critical",
                    )
                )
            elif _BROAD_SYSTEM_PATHS.search(uri):
                findings.append(
                    self.finding(
                        target=f"resource:{name}",
                        title=f"Resource '{name}' exposes a system directory",
                        explanation=(
                            f"The resource URI ({uri}) reaches into a system "
                            f"directory. Even without credentials in the path, "
                            f"broad filesystem exposure widens every other issue "
                            f"on this server."
                        ),
                        remediation=(
                            "Narrow the resource to the smallest directory the "
                            "model actually needs, and prefer read-only, "
                            "content-scoped resources over raw filesystem paths."
                        ),
                        severity="high",
                    )
                )
        return findings
