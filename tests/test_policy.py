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


def test_severity_overrides_change_fail_decision():
    manifest = {
        "server": {"name": "s"},
        "tools": [
            {
                "name": "run_shell",
                "description": "Run a shell command.",
                "inputSchema": {"properties": {"command": {"type": "string"}}},
            }
        ],
    }
    policy = AuditPolicy(severity_overrides={"broad_tool": "low"})
    report = audit_server(manifest, policy=policy)
    assert report.findings
    assert all(f.severity == "low" for f in report.findings if f.check_id == "broad_tool")
    assert policy.passes(report)


def test_severity_override_can_raise():
    # Overrides are applied at audit time: report findings carry the final
    # severity, and passes() reads them as-is.
    policy = AuditPolicy(fail_on="high", severity_overrides={"no_rate_limit": "critical"})
    manifest = {
        "server": {"name": "s"},
        "tools": [
            {
                "name": "server_time",
                "description": "Return the server time.",
                "annotations": {"readOnlyHint": True},
            }
        ],
    }
    report = audit_server(manifest, policy=policy)
    assert report.findings
    assert all(f.severity == "critical" for f in report.findings)
    assert not policy.passes(report)


def test_severity_overrides_reject_bad_severity():
    import pytest

    with pytest.raises(ValueError):
        AuditPolicy(severity_overrides={"broad_tool": "extreme"})


def test_severity_overrides_roundtrip():
    policy = AuditPolicy(
        fail_on="medium",
        disabled_checks=["verbose_errors"],
        allowlist={"no_rate_limit": ["tool:x"]},
        severity_overrides={"broad_tool": "low"},
    )
    restored = AuditPolicy.from_dict(policy.to_dict())
    assert restored == policy
