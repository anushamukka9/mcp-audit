"""Policy layer tests: thresholds, disabled checks, allowlists."""

from mcp_audit import AuditPolicy, audit_server
from mcp_audit.core import Finding


def _finding(check_id="broad_tool", severity="high", target="tool:x"):
    return Finding(
        check_id=check_id,
        severity=severity,
        target=target,
        title="t",
        explanation="e",
        remediation="r",
    )


def _report(*findings):
    from mcp_audit import AuditReport

    return AuditReport(manifest_name="s", findings=list(findings))


def test_default_policy_fails_on_high():
    policy = AuditPolicy()
    assert not policy.passes(_report(_finding(severity="high")))
    assert policy.passes(_report(_finding(severity="medium")))
    assert policy.passes(_report(_finding(severity="low")))


def test_fail_on_never_always_passes():
    policy = AuditPolicy(fail_on="never")
    assert policy.passes(_report(_finding(severity="critical")))


def test_fail_on_critical():
    policy = AuditPolicy(fail_on="critical")
    assert policy.passes(_report(_finding(severity="high")))
    assert not policy.passes(_report(_finding(severity="critical")))


def test_disabled_checks_are_filtered():
    policy = AuditPolicy(disabled_checks=["broad_tool"])
    report = audit_server(
        {
            "server": {"name": "s"},
            "tools": [
                {
                    "name": "run_shell",
                    "description": "Run a shell command.",
                    "inputSchema": {"properties": {"command": {"type": "string"}}},
                }
            ],
        },
        policy=policy,
    )
    assert all(f.check_id != "broad_tool" for f in report.findings)


def test_allowlist_suppresses_target():
    policy = AuditPolicy(allowlist={"no_rate_limit": ["tool:search_docs"]})
    report = audit_server(
        {
            "server": {"name": "s"},
            "tools": [
                {
                    "name": "search_docs",
                    "description": "Search docs.",
                    "annotations": {"readOnlyHint": True},
                }
            ],
        },
        policy=policy,
    )
    assert report.findings == []


def test_from_dict_roundtrip():
    policy = AuditPolicy.from_dict(
        {
            "fail_on": "medium",
            "disabled_checks": ["verbose_errors"],
            "allowlist": {"no_rate_limit": ["tool:x"]},
        }
    )
    assert policy.fail_on == "medium"
    assert policy.disabled_checks == ["verbose_errors"]
    assert policy.to_dict()["allowlist"] == {"no_rate_limit": ["tool:x"]}


def test_from_dict_defaults():
    policy = AuditPolicy.from_dict({})
    assert policy.fail_on == "high"
    assert policy.disabled_checks == []
    assert policy.allowlist == {}


def test_invalid_fail_on_rejected():
    import pytest

    with pytest.raises(ValueError):
        AuditPolicy(fail_on="extreme")
