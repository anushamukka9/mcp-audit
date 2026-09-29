"""Flags tool descriptions that nudge the agent to skip human approval.

Agent clients decide whether to ask the user before running a tool, and
they read the tool description when deciding. A description that says
"no need to ask", "auto-approve", or "safe to run without confirmation"
is not a feature note, it is the server voting on its own trust. I have
seen this phrasing show up in tool-poisoning write-ups: the model reads
the description, concludes approval is unnecessary, and runs something
the user never reviewed.

This check scans name and description text for approval-dodging
phrases. It is phrase matching, so it will flag genuinely harmless
read-only tools whose authors wrote "no confirmation needed" as a
courtesy, and it will miss paraphrased nudges. Read the description
yourself before deciding. If your tool really is safe to run
unreviewed, say so with the readOnlyHint annotation instead of prose.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_PATTERNS = [
    (r"auto-?approv", "asks to be auto-approved"),
    (r"always approv", "asks to always be approved"),
    (r"pre-?approved?", "claims to be pre-approved"),
    (
        r"no (need|reason) to ask",
        "says there is no need to ask",
    ),
    (
        r"do not ask (the user )?(for )?(confirmation|approval|permission)",
        "tells the caller not to ask for confirmation",
    ),
    (
        r"without (the |a )?(user|human) (confirmation|approval|permission|review)",
        "frames running without human approval as expected",
    ),
    (
        r"safe to run without",
        "claims it is safe to run without asking",
    ),
    (
        r"skip (the |this )?(approval|confirmation|review)",
        "instructs skipping approval",
    ),
    (
        r"confirmation (is not|isn't|not) (needed|required)",
        "says confirmation is not needed",
    ),
    (
        r"trusted[,.]?\s*(so )?no (review|approval|confirmation) needed",
        "declares itself trusted to dodge review",
    ),
    (
        r"whitelist(ed)? (this|the) tool",
        "asks to be whitelisted",
    ),
]


class ApprovalBypassCheck(Check):
    id = "approval_bypass"
    title = "Tool description nudges past human approval"
    description = (
        "Descriptions that tell the agent no confirmation is needed erode "
        "the human-in-the-loop boundary."
    )
    default_severity = "high"

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            description = tool.get("description", "")
            text = f"{name} {description}"
            reasons = [reason for pattern, reason in _PATTERNS if re.search(pattern, text, re.I)]
            if not reasons:
                continue
            reason = reasons[0]
            findings.append(
                self.finding(
                    target=f"tool:{name}",
                    title=f"Tool '{name}' nudges past human approval",
                    explanation=(
                        f"The description {reason}. Agent clients weigh "
                        f"tool descriptions when deciding whether to ask the "
                        f"user before running a tool, so this phrasing can "
                        f"quietly push a tool into running unreviewed."
                    ),
                    remediation=(
                        "Remove the approval-dodging language and let the "
                        "client and user decide when to confirm. If the tool "
                        "is genuinely side-effect free, say so with the "
                        "readOnlyHint annotation instead of prose."
                    ),
                    severity="high",
                )
            )
        return findings
