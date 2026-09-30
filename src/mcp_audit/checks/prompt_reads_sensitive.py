"""Flags prompt templates that reach for sensitive material.

A prompt template is instruction text the model executes with its own
privileges, and its output goes back to the user. When the template
references credential files, secret stores, or API keys, or tells the
model to read them, the server is one substitution away from handing
secrets to the output. Three shapes:

- the template names a sensitive path (reuses the sensitive_resource
  path patterns),
- the template instructs reading secrets, credentials, passwords, or keys,
- the template embeds secret-shaped placeholders like ``{api_key}``.

Templates legitimately mention credentials in passing ("never log the
password"), so a negation filter skips "do not / never" phrasing. Every
hit still needs a human read; the check points at the shape, not the
verdict.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_READ_SECRET = re.compile(
    r"\b(read|fetch|load|retrieve|get|dump|print|show|include|embed)\b"
    r".{0,40}\b(secret|secrets|credential|credentials|password|passwd|api[_-]?key|"
    r"private[_-]?key|access[_-]?token|auth[_-]?token)\b",
    re.I,
)
# Same sensitive-path idea as sensitive_resource, but path-shaped: the bare
# word "credentials" in prose must not count, only actual paths.
_TEMPLATE_SENSITIVE_PATH = re.compile(
    r"(?<![\w/])(/[A-Za-z0-9_.\-/]*?(passwd|shadow|sudoers|credentials|secrets)[A-Za-z0-9_.\-/]*"
    r"|\.pem\b|\.key\b|\.env\b|id_rsa|id_ed25519|\.aws/credentials)",
    re.I,
)
_SECRET_PLACEHOLDER = re.compile(
    r"\{[^}]*(secret|credential|password|passwd|api[_-]?key|private[_-]?key|token)[^}]*\}",
    re.I,
)
_NEGATED = re.compile(r"\b(do not|don't|never|without|avoid)\b", re.I)


class PromptReadsSensitiveCheck(Check):
    id = "prompt_reads_sensitive"
    title = "Prompt template reaches for sensitive material"
    description = (
        "Prompt templates that reference credential files or instruct the "
        "model to read secrets make disclosure the default behavior."
    )
    default_severity = "high"
    severity_rationale = (
        "High because templates run with model privileges and their output goes "
        "back to the user. A template that reaches for secrets makes disclosure "
        "the default behavior rather than an accident."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for prompt in self.prompts(manifest):
            name = prompt.get("name", "?")
            template = prompt.get("template", "") or ""
            hit = None
            if _TEMPLATE_SENSITIVE_PATH.search(template):
                hit = "references a sensitive file path"
            else:
                for match in _READ_SECRET.finditer(template):
                    before = template[max(0, match.start() - 30) : match.start()]
                    if _NEGATED.search(before):
                        continue
                    hit = "instructs the model to read secrets or credentials"
                    break
            if hit is None and _SECRET_PLACEHOLDER.search(template):
                hit = "embeds a secret-shaped placeholder"
            if hit is None:
                continue
            findings.append(
                self.finding(
                    target=f"prompt:{name}",
                    title=f"Prompt '{name}' {hit}",
                    explanation=(
                        f"The template {hit}. Templates execute with model "
                        f"privileges and their output returns to the user, so a "
                        f"template that reaches for secrets makes disclosure the "
                        f"default outcome, not an accident."
                    ),
                    remediation=(
                        "Keep secrets server-side and out of templates. If the "
                        "prompt genuinely needs a credential, pass it as a "
                        "server-held variable, never as template text or a "
                        "user-filled placeholder."
                    ),
                )
            )
        return findings
