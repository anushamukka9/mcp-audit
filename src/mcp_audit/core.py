"""Shared building blocks for mcp-audit.

A manifest is a plain dict describing an MCP server:

    {
        "server": {"name": "my-server", "version": "1.0.0"},
        "tools": [
            {
                "name": "read_file",
                "description": "Read a file from the docs folder.",
                "inputSchema": {"type": "object", "properties": {...}},
                "annotations": {"readOnlyHint": True},
            }
        ],
        "resources": [{"uri": "file:///docs/guide.md", "name": "guide"}],
        "prompts": [{"name": "summarize", "template": "Summarize: {text}"}],
    }

Everything here is deterministic. No model calls, no network.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

SEVERITIES = [CRITICAL, HIGH, MEDIUM, LOW]
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


def severity_at_or_above(severity: str, threshold: str) -> bool:
    """True if severity is at least as bad as threshold."""
    return _SEVERITY_RANK[severity] <= _SEVERITY_RANK[threshold]


@dataclass
class Finding:
    """One security issue found by one check."""

    check_id: str
    severity: str
    target: str
    title: str
    explanation: str
    remediation: str
    severity_rationale: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "severity_rationale": self.severity_rationale,
            "target": self.target,
            "title": self.title,
            "explanation": self.explanation,
            "remediation": self.remediation,
        }


@dataclass
class AuditReport:
    """The full result of auditing one manifest."""

    manifest_name: str
    findings: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def highest_severity(self) -> str | None:
        for severity in SEVERITIES:
            if any(f.severity == severity for f in self.findings):
                return severity
        return None

    def findings_for(self, check_id: str) -> list[Finding]:
        return [f for f in self.findings if f.check_id == check_id]

    def to_dict(self) -> dict:
        return {
            "manifest": self.manifest_name,
            "summary": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        }


class Check(ABC):
    """One audit check. Subclass, set id/title/description, implement run()."""

    id: str = ""
    title: str = ""
    description: str = ""
    default_severity: str = MEDIUM
    #: One or two sentences explaining why findings from this check get
    #: their severity. Surfaced in Finding.severity_rationale and the
    #: markdown/HTML reports so the rating is never a bare label.
    severity_rationale: str = ""

    def tools(self, manifest: dict) -> list[dict]:
        return manifest.get("tools", []) or []

    def resources(self, manifest: dict) -> list[dict]:
        return manifest.get("resources", []) or []

    def prompts(self, manifest: dict) -> list[dict]:
        return manifest.get("prompts", []) or []

    @abstractmethod
    def run(self, manifest: dict) -> list[Finding]:
        """Return findings for this check against the manifest."""
        raise NotImplementedError

    def finding(
        self,
        target: str,
        title: str,
        explanation: str,
        remediation: str,
        severity: str | None = None,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity or self.default_severity,
            target=target,
            title=title,
            explanation=explanation,
            remediation=remediation,
            severity_rationale=self.severity_rationale,
        )
