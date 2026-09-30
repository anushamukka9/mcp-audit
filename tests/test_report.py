"""Report formatter tests: every format renders, HTML escapes, rationale included."""

import json

import pytest

from mcp_audit import AuditPolicy, audit_server
from mcp_audit.report import _FORMATS, format_report


def _vuln_manifest():
    return {
        "server": {"name": "bad-server"},
        "tools": [
            {
                "name": "run_shell",
                "description": "Run a shell command.",
                "inputSchema": {"properties": {"command": {"type": "string"}}},
            },
        ],
    }


def _clean_manifest():
    return {
        "server": {"name": "good-server"},
        "tools": [
            {
                "name": "server_time",
                "description": "Return the server time.",
                "annotations": {"readOnlyHint": True, "rate_limit": "60/min"},
            },
        ],
    }


def test_all_formats_render():
    report = audit_server(_vuln_manifest())
    assert report.findings
    for fmt in _FORMATS:
        out = format_report(report, fmt)
        assert isinstance(out, str) and out.strip()


def test_unknown_format_raises():
    report = audit_server(_vuln_manifest())
    with pytest.raises(ValueError):
        format_report(report, "yaml")


def test_json_format_is_machine_readable():
    report = audit_server(_vuln_manifest())
    data = json.loads(format_report(report, "json"))
    assert data["manifest"] == "bad-server"
    assert data["findings"][0]["severity_rationale"]


def test_markdown_includes_rationale():
    report = audit_server(_vuln_manifest())
    md = format_report(report, "markdown")
    assert "Why high:" in md or "Why critical:" in md
    assert "## [" in md


def test_html_escapes_finding_text():
    from mcp_audit.core import AuditReport, Finding

    report = AuditReport(
        manifest_name="x",
        findings=[
            Finding(
                check_id="c",
                severity="high",
                target="tool:<b>t</b>",
                title='Title <script>alert("x")</script>',
                explanation="exp <i>y</i>",
                remediation="fix <u>z</u>",
                severity_rationale="why <b>high</b>",
            )
        ],
    )
    out = format_report(report, "html")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "&lt;b&gt;" in out


def test_html_includes_rationale():
    report = audit_server(_vuln_manifest())
    out = format_report(report, "html")
    assert "Why " in out
    assert "mcp-audit" in out


def test_clean_report_formats():
    report = audit_server(_clean_manifest())
    assert report.findings == []
    assert "No findings" in format_report(report, "table")
    assert "No findings" in format_report(report, "markdown")
    assert "No findings" in format_report(report, "html")


def test_sarif_rule_count_matches_checks():
    from mcp_audit import default_checks

    report = audit_server(_vuln_manifest())
    sarif = json.loads(format_report(report, "sarif"))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == len(default_checks())
    assert sarif["runs"][0]["results"]


def test_cli_html_format(tmp_path, capsys):
    from mcp_audit.cli import main

    manifest_path = tmp_path / "m.json"
    manifest_path.write_text(json.dumps(_vuln_manifest()))
    rc = main(["scan", str(manifest_path), "--format", "html", "--fail-on", "never"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "<!DOCTYPE html>" in out


def test_every_check_has_a_rationale():
    from mcp_audit import default_checks

    for check in default_checks():
        assert check.severity_rationale, check.id


def test_findings_carry_rationale_through_policy():
    policy = AuditPolicy()
    report = audit_server(_vuln_manifest(), policy=policy)
    assert all(f.severity_rationale for f in report.findings)
