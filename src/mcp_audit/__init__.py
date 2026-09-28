"""mcp-audit: security auditing for MCP servers.

Point it at a server manifest (the tools, resources, and prompts your MCP
server exposes) and it flags the security issues it can see statically:
injected instructions in descriptions, overly broad tools, dangerous tool
pairs, exposed secrets, and more. Deterministic, no model calls.

Quickstart:
    from mcp_audit import audit_server

    report = audit_server(manifest)
    for finding in report.findings:
        print(finding.severity, finding.target, finding.title)

    # or from the command line:
    # mcp-audit scan manifest.json
"""

from .checks import Check, check_by_id, default_checks
from .core import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    SEVERITIES,
    AuditReport,
    Finding,
)
from .policy import AuditPolicy

__version__ = "0.2.0"


def audit_server(
    manifest: dict,
    checks: list[Check] | None = None,
    policy: AuditPolicy | None = None,
) -> AuditReport:
    """Audit one MCP server manifest. Returns an AuditReport.

    Pass a custom check list to run a subset, and an AuditPolicy to have
    disabled checks and allowlists applied before you read the findings.
    With a policy, report.findings only contains the active findings.
    """
    policy = policy or AuditPolicy()
    name = (manifest.get("server", {}) or {}).get("name", "manifest")
    findings: list[Finding] = []
    for check in checks or default_checks():
        if not policy.check_enabled(check.id):
            continue
        for finding in check.run(manifest):
            if not policy.target_allowed(finding.check_id, finding.target):
                findings.append(finding)
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.check_id, f.target))
    return AuditReport(manifest_name=name, findings=findings)


__all__ = [
    "AuditPolicy",
    "AuditReport",
    "CRITICAL",
    "Check",
    "Finding",
    "HIGH",
    "LOW",
    "MEDIUM",
    "SEVERITIES",
    "audit_server",
    "check_by_id",
    "default_checks",
]
