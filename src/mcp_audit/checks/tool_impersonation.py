"""Flags tool names that impersonate trusted or system tools.

A tool named "system_exec", "admin_delete", or "anthropic_secure_lookup"
borrows authority it has not earned: models and users alike treat
official-sounding names as safer than they are, and a malicious server can
use that trust to get its tools picked first. This check is purely about
naming. A name is cosmetic; it proves nothing about what the tool does.
But naming is also cheap to fix, so there is no reason to keep a
suspicious one.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_IMPERSONATING_PREFIX = re.compile(
    r"^(system|admin|root|internal|private|secure|trusted)[-_]", re.I
)
_SENSITIVE_NAMES = re.compile(r"^(sudo|su|exec|eval|shell|chmod|chown)$", re.I)
_BRAND = re.compile(r"(anthropic|openai|Muse|gpt|gemini|Meta)", re.I)


class ToolImpersonationCheck(Check):
    id = "tool_impersonation"
    title = "Tool name impersonates a trusted tool"
    description = (
        "Names borrowing system, admin, or vendor authority make a tool look "
        "more trustworthy than it is."
    )
    default_severity = "medium"

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            reason = None
            if _IMPERSONATING_PREFIX.match(name):
                reason = "uses a system/admin-style prefix that implies privileged status"
            elif _SENSITIVE_NAMES.match(name):
                reason = "matches the name of a sensitive system command"
            elif _BRAND.search(name):
                reason = "borrows a vendor or model brand name"
            if reason:
                findings.append(
                    self.finding(
                        target=f"tool:{name}",
                        title=f"Tool '{name}' has a misleading name",
                        explanation=(
                            f"The tool name {reason}. Models tend to prefer "
                            f"official-sounding tools, so a misleading name can "
                            f"steer tool choice."
                        ),
                        remediation=(
                            "Rename the tool to describe what it does without "
                            "claiming authority it does not have."
                        ),
                    )
                )
        return findings
