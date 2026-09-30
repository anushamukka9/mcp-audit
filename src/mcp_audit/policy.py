"""Severity policy layer: fail thresholds, disabled checks, per-check allowlists.

A policy answers one question: does this audit pass? Configure it in code
or load it from a JSON file (see docs/configuration.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .core import CRITICAL, HIGH, LOW, MEDIUM, SEVERITIES, AuditReport, severity_at_or_above


@dataclass
class AuditPolicy:
    """Knobs for turning an AuditReport into a pass/fail decision."""

    fail_on: str = HIGH
    disabled_checks: list[str] = field(default_factory=list)
    allowlist: dict[str, list[str]] = field(default_factory=dict)
    #: Per-check severity overrides, as {check_id: severity}. Applied to
    #: findings before the fail_on decision, so lowering a noisy check or
    #: raising one you care about changes what fails the build.
    severity_overrides: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.fail_on != "never" and self.fail_on not in SEVERITIES:
            raise ValueError(f"fail_on must be one of {SEVERITIES} or 'never'")
        for check_id, severity in self.severity_overrides.items():
            if severity not in SEVERITIES:
                raise ValueError(
                    f"severity_overrides[{check_id!r}] must be one of {SEVERITIES}, "
                    f"got {severity!r}"
                )

    def check_enabled(self, check_id: str) -> bool:
        return check_id not in self.disabled_checks

    def target_allowed(self, check_id: str, target: str) -> bool:
        return target in self.allowlist.get(check_id, [])

    def active_findings(self, report: AuditReport) -> list:
        """Findings that survive disabled checks and allowlists."""
        active = []
        for finding in report.findings:
            if not self.check_enabled(finding.check_id):
                continue
            if self.target_allowed(finding.check_id, finding.target):
                continue
            active.append(finding)
        return active

    def passes(self, report: AuditReport) -> bool:
        """True when no active finding meets the fail threshold."""
        if self.fail_on == "never":
            return True
        return not any(
            severity_at_or_above(f.severity, self.fail_on) for f in self.active_findings(report)
        )

    def severity_for(self, check_id: str, default: str) -> str:
        """The effective severity for a check after overrides."""
        return self.severity_overrides.get(check_id, default)

    @classmethod
    def from_dict(cls, data: dict) -> AuditPolicy:
        return cls(
            fail_on=data.get("fail_on", HIGH),
            disabled_checks=list(data.get("disabled_checks", [])),
            allowlist={k: list(v) for k, v in data.get("allowlist", {}).items()},
            severity_overrides=dict(data.get("severity_overrides", {})),
        )

    def to_dict(self) -> dict:
        return {
            "fail_on": self.fail_on,
            "disabled_checks": list(self.disabled_checks),
            "allowlist": {k: list(v) for k, v in self.allowlist.items()},
            "severity_overrides": dict(self.severity_overrides),
        }


__all__ = ["AuditPolicy", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
