"""Fixture server tests: the example builds a manifest the scanner finds issues in."""

import sys
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
sys.path.insert(0, str(EXAMPLES))

import audit_fixture_server  # noqa: E402

from mcp_audit import audit_server, default_checks  # noqa: E402


def test_fixture_manifest_builds():
    manifest = audit_fixture_server.build_manifest()
    assert manifest["server"]["name"] == "fixture-vulnerable-server"
    assert len(manifest["tools"]) >= 8
    assert len(manifest["resources"]) == 2
    assert len(manifest["prompts"]) == 2
    assert all(p["template"] for p in manifest["prompts"])


def test_fixture_triggers_every_check():
    report = audit_server(audit_fixture_server.build_manifest())
    fired = {f.check_id for f in report.findings}
    expected = {c.id for c in default_checks()}
    assert fired == expected


def test_fixture_has_critical_findings():
    report = audit_server(audit_fixture_server.build_manifest())
    assert report.counts()["critical"] >= 1
    assert report.counts()["high"] >= 1


def test_fixture_example_fails_policy():
    rc = audit_fixture_server.main(["--format", "table"])
    assert rc == 1


def test_fixture_example_bad_format():
    with pytest.raises(ValueError):
        audit_fixture_server.main(["--format", "yaml"])
