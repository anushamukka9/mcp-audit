"""Flags state-changing tools with no auth annotation.

MCP annotations are advisory hints, and one of the useful ones is whether a
tool expects the caller to be authenticated. A tool that writes, deletes,
sends, or executes things but carries no auth annotation is either missing
access control or missing the documentation for it. Either way it deserves
a look. This check cannot verify that the server actually enforces auth;
it only reads the manifest. Read-only tools are skipped.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_MUTATING = re.compile(
    r"\b(write|save|create|update|delete|remove|send|post|publish|execute|exec|run|deploy|modify)\b",
    re.I,
)
_AUTH_KEYS = ("auth", "auth_required", "requires_auth", "authenticated")


class MissingAuthCheck(Check):
    id = "missing_auth"
    title = "State-changing tool without auth annotation"
    description = (
        "Tools that change state should say who is allowed to call them. "
        "Missing auth annotations suggest missing (or undocumented) access control."
    )
    default_severity = "medium"

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            annotations = tool.get("annotations", {}) or {}
            if annotations.get("readOnlyHint"):
                continue
            if any(annotations.get(key) for key in _AUTH_KEYS):
                continue
            text = f"{name} {tool.get('description', '')}"
            if annotations.get("destructiveHint") or _MUTATING.search(text):
                findings.append(
                    self.finding(
                        target=f"tool:{name}",
                        title=f"Tool '{name}' changes state but has no auth annotation",
                        explanation=(
                            "The tool looks state-changing (its name, description, or "
                            "annotations suggest writes, sends, or execution) but the "
                            "manifest carries no auth annotation, so clients cannot "
                            "tell whether calls are access-controlled."
                        ),
                        remediation=(
                            "Add an auth annotation to the tool and enforce it "
                            "server-side. If the tool is intentionally open, note "
                            "that explicitly so the absence looks deliberate."
                        ),
                    )
                )
        return findings
