"""Flags client config entries that pipe downloads into a shell.

The classic ``curl https://... | sh`` in a stdio entry's command or args
means the client executes whatever the URL serves, on every launch, with
the user's privileges. It is the install-script pattern transplanted
into a config file, and it deserves the same suspicion.

Fires on curl/wget/fetch piped into sh/bash/zsh/powershell, or a shell
``-c`` string containing a URL fetch. Reads
``manifest["client_servers"]`` from
``mcp_audit.client_config.scan_client_config``; silent on ordinary
server manifests.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_PIPE_TO_SHELL = re.compile(
    r"\b(curl|wget|fetch)\b[^|]*\|\s*(sh|bash|zsh|powershell|pwsh)\b",
    re.I,
)
_SHELL_C_URL = re.compile(
    r"\b(sh|bash|zsh)\b\s+(-c\s+)?['\"]?[^'\"]*\bhttps?://",
    re.I,
)


class ConfigShellPipeCheck(Check):
    id = "config_shell_pipe"
    title = "Client config pipes a download into a shell"
    description = (
        "A stdio MCP server entry runs a command shaped like "
        "'curl <url> | sh'. The client executes whatever the URL serves, "
        "on every launch."
    )
    default_severity = "high"
    severity_rationale = (
        "High because it is remote code execution by design: the bytes the "
        "server runs are whatever the URL returns at launch time, and they "
        "run with the user's privileges."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for server in manifest.get("client_servers", []) or []:
            if server.get("transport") != "stdio":
                continue
            command = str(server.get("command", "") or "")
            args = " ".join(str(a) for a in (server.get("args") or []))
            blob = f"{command} {args}"
            if not (_PIPE_TO_SHELL.search(blob) or _SHELL_C_URL.search(blob)):
                continue
            name = server.get("name", "?")
            source = server.get("source", "config")
            findings.append(
                self.finding(
                    target=f"server:{name}",
                    title=f"'{name}' pipes a download into a shell",
                    explanation=(
                        f"The {source} config entry '{name}' runs "
                        f"'{blob.strip()}', which fetches a URL and pipes it "
                        "into a shell. The client executes whatever that URL "
                        "serves on every launch, with your user's privileges. "
                        "A compromised or typosquatted URL is instant code "
                        "execution."
                    ),
                    remediation=(
                        "Download the script once, read it, pin it locally, "
                        "and point the entry at the local file. If the "
                        "server needs frequent updates, switch to a version "
                        "pinned package instead of a live pipe."
                    ),
                )
            )
        return findings
