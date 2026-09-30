"""Flags inconsistent auth annotations across state-changing tools.

Some tools on the server carry auth annotations while other state-changing
tools do not. Either the unannotated tools are access-controlled and the
authors forgot to say so, or they are genuinely open. The inconsistency
itself is the finding: clients reading the manifest cannot tell which
tools are safe to expose, and reviewers cannot tell which ones still need
access control.

Read-only tools (readOnlyHint) are excluded from the unannotated side.
This check only reads annotations; it cannot verify what the server
actually enforces. One inconsistent server gets one finding, naming the
tools on each side.
"""

from __future__ import annotations

from ..core import Finding
from .base import Check
from .missing_auth import _AUTH_KEYS, _MUTATING


class PrivilegeMixingCheck(Check):
    id = "privilege_mixing"
    title = "Inconsistent auth annotations across tools"
    description = (
        "Some state-changing tools carry auth annotations while others do not, "
        "so clients cannot tell which calls are access-controlled."
    )
    default_severity = "medium"
    severity_rationale = (
        "Medium because inconsistency is a smell, not a vulnerability. It means "
        "either missing access control or missing documentation, and the server "
        "owner needs to say which."
    )

    def _has_auth(self, tool: dict) -> bool:
        annotations = tool.get("annotations", {}) or {}
        return any(annotations.get(key) for key in _AUTH_KEYS)

    def _is_state_changing(self, tool: dict) -> bool:
        annotations = tool.get("annotations", {}) or {}
        if annotations.get("readOnlyHint"):
            return False
        text = f"{tool.get('name', '')} {tool.get('description', '')}"
        return bool(annotations.get("destructiveHint") or _MUTATING.search(text))

    def run(self, manifest: dict) -> list[Finding]:
        tools = self.tools(manifest)
        authed = sorted(t.get("name", "?") for t in tools if self._has_auth(t))
        unauthed = sorted(
            t.get("name", "?")
            for t in tools
            if self._is_state_changing(t) and not self._has_auth(t)
        )
        if not authed or not unauthed:
            return []
        name = (manifest.get("server", {}) or {}).get("name", "server")
        return [
            self.finding(
                target=f"server:{name}",
                title="Auth annotations are applied inconsistently",
                explanation=(
                    f"These tools declare auth ({', '.join(authed)}) but these "
                    f"state-changing tools do not ({', '.join(unauthed)}). Either "
                    f"the second group is missing access control or missing "
                    f"documentation; the manifest alone cannot tell you which."
                ),
                remediation=(
                    "Annotate every tool's auth expectation, including the ones "
                    "that are intentionally open. If the unannotated tools are "
                    "enforced server-side, say so; if they are not, add the "
                    "enforcement."
                ),
            )
        ]
