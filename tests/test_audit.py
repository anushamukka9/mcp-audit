"""Integration tests for audit_server: ordering, naming, policy interplay."""

from mcp_audit import AuditPolicy, audit_server
from mcp_audit.checks import default_checks


def test_all_checks_have_unique_ids():
    ids = [c.id for c in default_checks()]
    assert len(ids) == len(set(ids)) == 14


def test_all_checks_have_docs():
    for check in default_checks():
        assert check.title, check.id
        assert check.description, check.id


def test_findings_sorted_by_severity():
    manifest = {
        "server": {"name": "s"},
        "tools": [
            {
                "name": "search_docs",
                "description": "Search docs.",
                "annotations": {"readOnlyHint": True},
            },
            {
                "name": "run_shell",
                "description": "Run a shell command.",
                "inputSchema": {"properties": {"command": {"type": "string"}}},
            },
        ],
    }
    report = audit_server(manifest)
    severities = [f.severity for f in report.findings]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert severities == sorted(severities, key=lambda s: rank[s])
    assert severities[0] == "critical"


def test_report_counts_and_highest():
    manifest = {
        "server": {"name": "s"},
        "tools": [
            {
                "name": "run_shell",
                "description": "Run a shell command.",
                "inputSchema": {"properties": {"command": {"type": "string"}}},
            },
        ],
    }
    report = audit_server(manifest)
    counts = report.counts()
    assert counts["critical"] == 1
    assert sum(counts.values()) == len(report.findings)
    assert report.highest_severity() == "critical"


def test_manifest_name_defaults():
    report = audit_server({})
    assert report.manifest_name == "manifest"


def test_to_dict_shape():
    report = audit_server({"server": {"name": "s"}, "tools": []})
    data = report.to_dict()
    assert set(data) == {"manifest", "summary", "findings"}
    assert data["manifest"] == "s"


def test_policy_allowlist_end_to_end():
    manifest = {
        "server": {"name": "s"},
        "tools": [
            {
                "name": "search_docs",
                "description": "Search docs.",
                "annotations": {"readOnlyHint": True},
            }
        ],
    }
    plain = audit_server(manifest)
    assert len(plain.findings) == 1  # no_rate_limit
    policy = AuditPolicy(allowlist={"no_rate_limit": ["tool:search_docs"]})
    filtered = audit_server(manifest, policy=policy)
    assert filtered.findings == []
