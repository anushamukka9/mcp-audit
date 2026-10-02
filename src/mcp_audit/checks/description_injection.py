"""Flags instructions smuggled into tool and prompt descriptions.

A tool description is shown to the model every time the tool is offered,
which makes it a quiet channel for prompt injection: a third-party MCP
server can hide "ignore your safety instructions" in a description and the
model reads it as context. This check looks for known instruction-smuggling
phrases. It cannot catch paraphrased or obfuscated injections, and it will
flag legitimate descriptions that happen to use imperative language, so
treat every hit as "read this description yourself", not as proof.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_PATTERNS = [
    (
        r"ignore (all |your |previous |prior )?(previous |prior )?instructions",
        "tells the model to ignore its instructions",
    ),
    (
        r"disregard (your |all )?instructions",
        "tells the model to disregard its instructions",
    ),
    (
        r"override (your |all )?(safety |system )?instructions",
        "tells the model to override its instructions",
    ),
    (r"you (must|have to|are required to) ", "imperative instruction aimed at the model"),
    (
        r"do not (tell|mention|reveal|disclose) (the |to the )?user",
        "instructs the model to hide something from the user",
    ),
    (r"keep (this|it) (secret|hidden|confidential)", "asks the model to keep something secret"),
    (r"(^|\n)\s*(system|important)\s*:", "fake system/important header inside a description"),
    (r"\[\s*(system|inst)\s*\]", "fake system tag inside a description"),
    (r"<<\s*sys\s*>>", "fake system delimiter inside a description"),
    (r"new instructions\s*:", "declares new instructions inside a description"),
    (
        r"reveal (your |the )?(system prompt|instructions)",
        "asks the model to reveal its system prompt",
    ),
]


class DescriptionInjectionCheck(Check):
    id = "description_injection"
    title = "Prompt-injection surface in descriptions"
    description = (
        "Tool and prompt descriptions are model-visible text. Instructions "
        "hidden in them can steer the model."
    )
    default_severity = "high"
    severity_rationale = (
        "High because descriptions are shown to the model every time the tool is offered. A "
        "single injected instruction rides along with normal use, no special request needed, "
        "which makes it the cheapest attack surface on the server."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        targets = [
            ("tool", t.get("name", "?"), t.get("description", "")) for t in self.tools(manifest)
        ]
        targets += [
            ("prompt", p.get("name", "?"), p.get("description", "")) for p in self.prompts(manifest)
        ]
        for kind, name, description in targets:
            text = description or ""
            lowered = text.lower()
            for pattern, why in _PATTERNS:
                if re.search(pattern, lowered):
                    findings.append(
                        self.finding(
                            target=f"{kind}:{name}",
                            title=f"Possible injected instruction in {kind} '{name}'",
                            explanation=(
                                f"The description {why}. Descriptions are shown to the "
                                f"model as context, so this text can influence model "
                                f"behavior every time the {kind} is offered."
                            ),
                            remediation=(
                                "Rewrite the description to describe only what the tool "
                                "does, with no imperative language aimed at the model. "
                                "If the phrasing is intentional, document why."
                            ),
                        )
                    )
                    break
        return findings
