"""Flags tools with dangerously broad capabilities.

Some tools are one confused model away from a real incident: arbitrary shell
execution, unrestricted file writes, or network fetch with no scoping. This
check matches tool names and descriptions against capability patterns. It is
a heuristic over documentation, not a sandbox analysis: a tool named
"shell" that only lists a directory will false-positive, and a tool with a
vague description ("does stuff") will slip through. Read the flagged tool's
actual implementation before deciding.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_SHELL = re.compile(
    r"\b(shell|bash|zsh|powershell|cmd\.exe|subprocess|os\.system|popen|exec)\b", re.I
)
_EXEC_PARAM = re.compile(r"\b(command|cmd|script|shellcode|argv)\b", re.I)
_WRITE = re.compile(
    r"\b(write|save|create|delete|remove|unlink|overwrite|truncate)\b"
    r".{0,20}\b(file|path|directory|folder)\b",
    re.I,
)
_WRITE_ALT = re.compile(r"\b(file|path)\b.{0,20}\b(write|save|delete|remove)\b", re.I)
_NETWORK = re.compile(r"\b(fetch|download|curl|wget|http\.get|http\.post|requests?\.)\b", re.I)
_SCOPED = re.compile(
    r"\b(allowlist|whitelist|allowed (domains?|hosts?|urls?)|restricted to)\b", re.I
)


class BroadToolCheck(Check):
    id = "broad_tool"
    title = "Overly broad tool capabilities"
    description = (
        "Shell execution, arbitrary file writes, and unscoped network access "
        "give a compromised or confused model far too much room."
    )
    default_severity = "high"

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            text = f"{name} {tool.get('description', '')}"
            schema = str(tool.get("inputSchema", ""))
            blob = f"{text} {schema}"

            if _SHELL.search(text) and _EXEC_PARAM.search(blob):
                findings.append(
                    self.finding(
                        target=f"tool:{name}",
                        title=f"Tool '{name}' allows arbitrary shell execution",
                        explanation=(
                            "The tool name or description indicates it runs shell "
                            "commands supplied as parameters. Any prompt injection "
                            "that reaches this tool becomes remote code execution."
                        ),
                        remediation=(
                            "Replace the generic shell tool with narrow, purpose-built "
                            "tools (for example 'list_directory' instead of 'run any "
                            "command'). If you must keep it, gate it behind an "
                            "approval step and an allowlisted command set."
                        ),
                        severity="critical",
                    )
                )
                continue

            if _WRITE.search(text) or _WRITE_ALT.search(text):
                findings.append(
                    self.finding(
                        target=f"tool:{name}",
                        title=f"Tool '{name}' writes or deletes arbitrary files",
                        explanation=(
                            "The tool appears to write, save, or delete files at "
                            "caller-supplied paths. A confused model can overwrite "
                            "or destroy data outside the intended scope."
                        ),
                        remediation=(
                            "Scope writes to a single directory, validate paths "
                            "against traversal (reject '..'), and require an "
                            "approval step for destructive operations."
                        ),
                        severity="high",
                    )
                )
                continue

            if _NETWORK.search(text) and not _SCOPED.search(text):
                findings.append(
                    self.finding(
                        target=f"tool:{name}",
                        title=f"Tool '{name}' fetches from the network without scoping",
                        explanation=(
                            "The tool performs network requests but its description "
                            "mentions no domain allowlist or scoping. That makes it "
                            "a ready-made exfiltration channel."
                        ),
                        remediation=(
                            "Restrict requests to an explicit domain allowlist and "
                            "say so in the description. Block private IP ranges to "
                            "stop SSRF against internal services."
                        ),
                        severity="high",
                    )
                )
        return findings
