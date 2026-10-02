"""Flags tools with no rate-limit hint in their annotations.

An MCP tool with no rate limiting is a tool a compromised client can call
ten thousand times: credential stuffing against a login tool, scraping
through a search tool, cost amplification against anything backed by a paid
API. This check looks for rate-limit annotations and flags tools that carry
none. Annotations are advisory, so a missing annotation does not prove the
server is unprotected; it proves the manifest does not say it is. Low
severity on purpose: this is hygiene, not a vulnerability.
"""

from __future__ import annotations

from ..core import Finding
from .base import Check

_RATE_LIMIT_KEYS = ("rate_limit", "rateLimit", "throttle", "throttled", "quota", "rate_limited")


class NoRateLimitCheck(Check):
    id = "no_rate_limit"
    title = "Tool without rate-limit annotation"
    description = (
        "Tools that say nothing about rate limiting invite abuse at scale: "
        "scraping, stuffing, and cost amplification."
    )
    default_severity = "low"
    severity_rationale = (
        "Low on purpose: this is hygiene, not a vulnerability. Missing rate limiting enables "
        "abuse at scale, but it needs a real flaw underneath to become an incident. Worth the "
        "flag, not the panic."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            annotations = tool.get("annotations", {}) or {}
            if any(annotations.get(key) for key in _RATE_LIMIT_KEYS):
                continue
            findings.append(
                self.finding(
                    target=f"tool:{name}",
                    title=f"Tool '{name}' has no rate-limit annotation",
                    explanation=(
                        "The manifest says nothing about rate limiting for this "
                        "tool. Without throttling, a compromised or abusive "
                        "client can call it as fast as the server allows."
                    ),
                    remediation=(
                        "Add server-side rate limiting and document it in the "
                        "tool annotations so clients can back off gracefully."
                    ),
                )
            )
        return findings
