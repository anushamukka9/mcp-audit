"""Flags secrets embedded in the manifest itself.

Manifests get committed to git, pasted into chat windows, and posted in
issues. An API key sitting in a tool description, or a password baked into
a resource URI, stops being a secret the moment the manifest is shared.
This check looks for the shapes secrets take: credentials in URIs
(https://user:password@host), private key blocks, api_key = "..."
assignments, bearer tokens, and known token shapes (sk-, ghp_, xoxb-,
AKIA...).

It is pattern matching, not secret validation. It cannot tell a real key
from a placeholder, and it misses secrets hidden behind indirection (an env
var named in the manifest is fine, by design). It never prints the matched
value in a finding. Treat a hit as "rotate it and move it server-side",
not as proof of compromise.
"""

from __future__ import annotations

import json
import re

from ..core import Finding
from .base import Check

_URI_USERINFO = re.compile(r"://[^/\s:]+:[^/\s@]+@")
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z][A-Z ]*PRIVATE KEY-----")
_API_KEY_ASSIGN = re.compile(
    r"\b(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret)\b\s*[:=]\s*[\"']?([A-Za-z0-9_.\-~+/=]{12,})[\"']?",
    re.I,
)
_PASSWORD_ASSIGN = re.compile(
    r"\b(passw(?:or)?d|passwd|pwd)\b\s*[:=]\s*(\S{4,})",
    re.I,
)
_BEARER = re.compile(r"\bbearer\s+([A-Za-z0-9_.\-~+/=]{12,})", re.I)
_TOKEN_SHAPE = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|xox[bap]-[A-Za-z0-9-]{10,}|"
    r"AKIA[0-9A-Z]{16})\b"
)


class EmbeddedSecretCheck(Check):
    id = "embedded_secret"
    title = "Secret embedded in the manifest"
    description = (
        "API keys, passwords, and private key material baked into "
        "descriptions or URIs leak the moment the manifest is shared."
    )
    default_severity = "high"

    def _scan(self, target: str, name: str, text: str, uri: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if uri and _URI_USERINFO.search(uri):
            findings.append(
                self.finding(
                    target=target,
                    title=f"Resource '{name}' embeds credentials in its URI",
                    explanation=(
                        f"The resource URI ({uri}) carries a username and "
                        f"password. Anyone who can read the manifest learns the "
                        f"credentials, and the URI will end up in logs, chat "
                        f"transcripts, and version control."
                    ),
                    remediation=(
                        "Move the credentials server-side: use an env var, a "
                        "secret manager, or the server's own auth config, and "
                        "keep the URI credential-free."
                    ),
                    severity="critical",
                )
            )
        if _PEM_BLOCK.search(text):
            findings.append(
                self.finding(
                    target=target,
                    title=f"Private key material inside {target}",
                    explanation=(
                        "The manifest contains a private key block. Key "
                        "material in a manifest is one git push away from being "
                        "public, and every client that fetches the manifest "
                        "gets a copy."
                    ),
                    remediation=(
                        "Delete the key from the manifest, rotate it (assume it "
                        "is compromised), and load keys from a secret manager "
                        "at runtime instead."
                    ),
                    severity="critical",
                )
            )
        if _API_KEY_ASSIGN.search(text) or _TOKEN_SHAPE.search(text) or _BEARER.search(text):
            findings.append(
                self.finding(
                    target=target,
                    title=f"API key or token embedded in {target}",
                    explanation=(
                        "The manifest text contains something shaped like an "
                        "API key or bearer token. Manifests travel further "
                        "than people expect: repos, docs, support tickets."
                    ),
                    remediation=(
                        "Rotate the credential, remove it from the manifest, "
                        "and reference it by name (env var or secret manager) "
                        "instead of by value."
                    ),
                    severity="high",
                )
            )
        if _PASSWORD_ASSIGN.search(text):
            findings.append(
                self.finding(
                    target=target,
                    title=f"Password embedded in {target}",
                    explanation=(
                        "The manifest text assigns a password inline. Inline "
                        "passwords get copied into places passwords should "
                        "never go."
                    ),
                    remediation=(
                        "Rotate the password and move it to the server's own "
                        "configuration, out of the manifest."
                    ),
                    severity="high",
                )
            )
        return findings

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            text = "\n".join(
                [name, tool.get("description", ""), json.dumps(tool.get("inputSchema", {}))]
            )
            findings += self._scan(f"tool:{name}", name, text)
        for resource in self.resources(manifest):
            name = resource.get("name", resource.get("uri", "?"))
            uri = resource.get("uri", "")
            findings += self._scan(f"resource:{name}", name, f"{name}\n{uri}", uri=uri)
        for prompt in self.prompts(manifest):
            name = prompt.get("name", "?")
            text = "\n".join([name, prompt.get("description", ""), prompt.get("template", "")])
            findings += self._scan(f"prompt:{name}", name, text)
        return findings
