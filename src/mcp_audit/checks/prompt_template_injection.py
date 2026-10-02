"""Flags prompt templates with injection vectors.

Prompt templates run with model privileges, so a template that embeds raw
user input next to instructions is an injection waiting to happen, and a
template that itself contains override-style language ("ignore the user's
request and...") bakes the attack into the server. This check looks for
injection phrases inside templates and for user-input placeholders sitting
in instruction-heavy text. Prompt templates legitimately contain
instructions, so every hit needs a human read; the check points at the
shape, not the verdict.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_INJECTION_PHRASES = re.compile(
    r"\b(ignore|disregard|override)\b.{0,30}\b(instructions|request|system)\b"
    r"|\breveal\b.{0,20}\b(system prompt|instructions)\b"
    r"|\bdo not (tell|mention) the user\b",
    re.I,
)
_PLACEHOLDER = re.compile(
    r"(\{[a-zA-Z_][a-zA-Z0-9_]*\}|\{\{[a-zA-Z_][^}]*\}\}|\$\{[a-zA-Z_][^}]*\})"
)
_INSTRUCTIONY = re.compile(r"\b(you (must|should|will)|never|always|strictly)\b", re.I)


class PromptTemplateInjectionCheck(Check):
    id = "prompt_template_injection"
    title = "Prompt template with injection vector"
    description = (
        "Templates that mix user input with instructions, or that carry "
        "override-style language themselves, are easy injection targets."
    )
    default_severity = "high"
    severity_rationale = (
        "High because templates run with model privileges and mix trusted instructions with "
        "untrusted input. A template that embeds raw user input next to instructions fires during "
        "normal use, not just under attack."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for prompt in self.prompts(manifest):
            name = prompt.get("name", "?")
            template = prompt.get("template", "") or ""
            if _INJECTION_PHRASES.search(template):
                findings.append(
                    self.finding(
                        target=f"prompt:{name}",
                        title=f"Prompt '{name}' contains override-style language",
                        explanation=(
                            "The template itself contains instruction-override "
                            "phrasing. Whether it is a leftover attack or an "
                            "unfortunate wording choice, a template that tells the "
                            "model to ignore instructions does not belong in a "
                            "server."
                        ),
                        remediation=(
                            "Rewrite the template to remove override phrasing. "
                            "Keep templates descriptive; put behavioral rules in "
                            "your application layer, not in shared templates."
                        ),
                    )
                )
            elif _PLACEHOLDER.search(template) and _INSTRUCTIONY.search(template):
                findings.append(
                    self.finding(
                        target=f"prompt:{name}",
                        title=f"Prompt '{name}' mixes user input with strong instructions",
                        explanation=(
                            "The template interpolates user-controlled input inside "
                            "instruction-heavy text. A user can smuggle their own "
                            "instructions into the placeholder and the model will "
                            "read them as part of the template."
                        ),
                        remediation=(
                            "Delimit user input clearly (quote it, or pass it as a "
                            "separate argument the template marks as untrusted "
                            "data), and keep imperative language away from the "
                            "interpolated regions."
                        ),
                    )
                )
        return findings
