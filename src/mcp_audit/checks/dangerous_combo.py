"""Flags dangerous tool combinations on the same server.

Individual tools can look innocent while the pair is the vulnerability:
a file reader plus a network sender is a data-exfiltration kit, and a shell
tool plus a network tool is a download-and-execute kit. Attackers chain
tools; audits should look at the set, not just each tool alone. Presence of
a pair does not prove exploitability, but it is exactly the shape real
exfiltration takes, so it is worth a deliberate decision.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_READ = re.compile(r"\b(read|cat|load|open|fetch_file|get_file)\b", re.I)
_FILE = re.compile(r"\b(file|document|secret|credential|config)\b", re.I)
_SEND = re.compile(r"\b(send|post|upload|exfil|webhook|email|http)\b", re.I)
_SHELL = re.compile(r"\b(shell|exec|bash|command)\b", re.I)


class DangerousComboCheck(Check):
    id = "dangerous_combo"
    title = "Dangerous tool combination"
    description = (
        "Pairs of tools that together enable exfiltration or remote execution, "
        "even when each tool looks reasonable alone."
    )
    default_severity = "high"
    severity_rationale = (
        "High because attackers chain tools, and this is exactly the shape real exfiltration "
        "takes: one tool reads the secret, the other moves it off the host. Each half looks "
        "innocent, which is why the pair earns the severity."
    )

    def _capabilities(self, tool: dict) -> set[str]:
        text = f"{tool.get('name', '')} {tool.get('description', '')}"
        caps = set()
        if _READ.search(text) and _FILE.search(text):
            caps.add("file_read")
        if _SEND.search(text):
            caps.add("network_send")
        if _SHELL.search(text):
            caps.add("shell")
        return caps

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        tools = self.tools(manifest)
        caps = {t.get("name", "?"): self._capabilities(t) for t in tools}

        readers = sorted(n for n, c in caps.items() if "file_read" in c)
        senders = sorted(n for n, c in caps.items() if "network_send" in c)
        shells = sorted(n for n, c in caps.items() if "shell" in c)

        if readers and senders:
            pair = f"{readers[0]} + {senders[0]}"
            findings.append(
                self.finding(
                    target=f"server:{pair}",
                    title=(
                        f"Exfiltration pair: '{readers[0]}' reads files, "
                        f"'{senders[0]}' sends data out"
                    ),
                    explanation=(
                        "One tool reads file-like content and another sends data "
                        "over the network. Together they form a complete "
                        "exfiltration path: a single prompt injection can read a "
                        "secret and post it somewhere you do not control."
                    ),
                    remediation=(
                        "Break the chain: scope the reader to non-sensitive "
                        "directories, restrict the sender to an allowlisted "
                        "destination, or require human approval when both are "
                        "used in one session."
                    ),
                )
            )
        if shells and senders:
            pair = f"{shells[0]} + {senders[0]}"
            findings.append(
                self.finding(
                    target=f"server:{pair}",
                    title=(
                        f"Download-and-execute pair: '{shells[0]}' runs commands, "
                        f"'{senders[0]}' reaches the network"
                    ),
                    explanation=(
                        "A command-execution tool plus a network tool is the classic "
                        "download-and-execute shape. An attacker who steers the "
                        "model can fetch a payload and run it."
                    ),
                    remediation=(
                        "Do not ship both capabilities in one server. If you need "
                        "both, sandbox execution and allowlist the network tool's "
                        "destinations."
                    ),
                )
            )
        return findings
