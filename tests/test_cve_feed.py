"""Tests for the CVE feed: parsing, version ranges, matching, the check.

The custom feed used here is test data on purpose: two invented entries
with precise ranges exercise the engine, while the bundled snapshot gets
its own small set of assertions (it loads, its entries are well-formed,
and the one name from the October disclosures matches).
"""

import json

import pytest

from mcp_audit import audit_server, load_feed
from mcp_audit.checks import check_by_id
from mcp_audit.checks.known_vulnerable_package import KnownVulnerablePackageCheck
from mcp_audit.cve_feed import (
    CveFeed,
    extract_package_candidates,
    normalize_package_name,
    parse_version,
    split_package_spec,
    version_satisfies,
)

TEST_FEED = CveFeed.from_dict(
    {
        "feed_version": 1,
        "updated": "2026-10-17",
        "entries": [
            {
                "id": "CVE-2099-0001",
                "package": "acme-mcp-server",
                "aliases": ["acme_mcp_server"],
                "affected": ">=1.0.0,<1.4.2",
                "severity": "critical",
                "summary": "Test entry: bad things in the old range.",
                "references": ["https://example.invalid/advisory"],
            },
            {
                "id": "CVE-2099-0002",
                "package": "@acme/widget-server",
                "affected": "<2.0.0",
                "severity": "high",
                "summary": "Test entry: scoped package.",
            },
        ],
    }
)


def _check():
    return KnownVulnerablePackageCheck(TEST_FEED)


def test_bundled_feed_loads_and_is_well_formed():
    feed = load_feed()
    assert feed.updated == "2026-10-17"
    assert feed.entries, "bundled snapshot must not ship empty"
    for entry in feed.entries:
        assert entry.id.startswith("CVE-")
        assert entry.package
        assert entry.severity in ("critical", "high", "medium", "low")


def test_bundled_feed_matches_ruflo_disclosure():
    feed = load_feed()
    matches = feed.match("ruflo")
    assert [m.id for m in matches] == ["CVE-2026-59726"]
    assert feed.match("ruflo-fork") == []
    assert feed.match("notes-server") == []


def test_parse_version():
    assert parse_version("1.2.3") == (1, 2, 3)
    assert parse_version("v1.2") == (1, 2)
    assert parse_version("1.2.3-rc1") == (1, 2, 3)
    assert parse_version("latest") is None
    assert parse_version("") is None
    assert parse_version(None) is None


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("1.4.1", ">=1.0.0,<1.4.2", True),
        ("1.4.2", ">=1.0.0,<1.4.2", False),
        ("0.9.9", ">=1.0.0,<1.4.2", False),
        ("9.9.9", "*", True),
        ("1.2", "<1.2.1", True),
        ("1.2.0", "==1.2", True),
        ("1.2.1", "!=1.2.1", False),
        ("2.0.0", "<=2.0.0", True),
    ],
)
def test_version_satisfies(version, spec, expected):
    assert version_satisfies(version, spec) is expected


def test_version_satisfies_unparseable_is_none():
    assert version_satisfies("not-a-version", "<2.0.0") is None


def test_normalize_package_name_folds_separators():
    assert normalize_package_name("Acme_MCP.Server") == "acme-mcp-server"


def test_split_package_spec():
    assert split_package_spec("acme-mcp-server@1.2.3") == ("acme-mcp-server", "1.2.3")
    assert split_package_spec("@acme/widget-server@2.0.0") == ("@acme/widget-server", "2.0.0")
    assert split_package_spec("acme-mcp-server") == ("acme-mcp-server", None)
    assert split_package_spec("acme-mcp-server@latest") == ("acme-mcp-server", None)
    assert split_package_spec("./local/server.py") is None
    assert split_package_spec("-y") is None


def test_confirmed_match_carries_entry_severity_and_cve():
    manifest = {"server": {"name": "acme-mcp-server", "version": "1.2.0"}}
    findings = _check().run(manifest)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "critical"
    assert "CVE-2099-0001" in finding.title
    assert "https://example.invalid/advisory" in finding.explanation
    assert finding.severity_rationale


def test_fixed_version_is_silent():
    manifest = {"server": {"name": "acme-mcp-server", "version": "1.4.2"}}
    assert _check().run(manifest) == []


def test_alias_and_separator_spelling_match():
    manifest = {"server": {"name": "whatever", "package": "acme_mcp_server", "version": "1.0.0"}}
    findings = _check().run(manifest)
    assert len(findings) == 1
    assert findings[0].target == "server:whatever"


def test_undeclared_version_is_medium_and_says_unconfirmed():
    manifest = {"server": {"name": "acme-mcp-server"}}
    findings = _check().run(manifest)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "version not declared" in findings[0].title


def test_similar_name_does_not_match():
    manifest = {"server": {"name": "acme-mcp-server-fork", "version": "1.2.0"}}
    assert _check().run(manifest) == []


def test_scoped_package_in_server_name_with_version_spec():
    manifest = {"server": {"name": "@acme/widget-server@1.5.0"}}
    findings = _check().run(manifest)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_dependency_entries_are_checked():
    manifest = {
        "server": {"name": "clean-front-door"},
        "dependencies": [
            {"name": "acme-mcp-server", "version": "1.1.0"},
            "unrelated-lib@3.0.0",
        ],
    }
    findings = _check().run(manifest)
    assert len(findings) == 1
    assert findings[0].target == "package:acme-mcp-server"


def test_client_config_runner_package_is_checked():
    manifest = {
        "server": {"name": "client-config:test.json"},
        "client_servers": [
            {
                "name": "acme",
                "source": "test.json",
                "transport": "stdio",
                "command": "npx",
                "args": ["-y", "acme-mcp-server@1.3.0"],
                "env": {},
            }
        ],
    }
    findings = _check().run(manifest)
    assert len(findings) == 1
    assert findings[0].target == "server:acme"


def test_client_config_local_script_is_not_a_package():
    manifest = {
        "server": {"name": "client-config:test.json"},
        "client_servers": [
            {
                "name": "local",
                "source": "test.json",
                "transport": "stdio",
                "command": "python",
                "args": ["/home/you/acme-mcp-server.py"],
                "env": {},
            }
        ],
    }
    assert _check().run(manifest) == []


def test_extract_candidates_dedupes():
    manifest = {"server": {"name": "acme-mcp-server", "version": "1.2.0"}}
    candidates = extract_package_candidates(manifest)
    assert len(candidates) == 1
    assert candidates[0].package == "acme-mcp-server"
    assert candidates[0].version == "1.2.0"


def test_default_checks_include_the_cve_check():
    check = check_by_id("known_vulnerable_package")
    assert check is not None
    assert check.severity_rationale


def test_audit_server_flags_bundled_ruflo():
    report = audit_server({"server": {"name": "ruflo", "version": "1.0.0"}})
    hits = report.findings_for("known_vulnerable_package")
    assert len(hits) == 1
    assert hits[0].severity == "critical"


def test_bad_feed_entry_rejected(tmp_path):
    path = tmp_path / "feed.json"
    path.write_text(json.dumps({"entries": [{"id": "CVE-1", "package": "x", "severity": "nope"}]}))
    with pytest.raises(ValueError):
        load_feed(path)


def test_cli_scan_with_custom_feed(tmp_path, capsys):
    from mcp_audit.cli import main

    feed_path = tmp_path / "feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "updated": "2026-10-17",
                "entries": [
                    {
                        "id": "CVE-2099-0001",
                        "package": "acme-mcp-server",
                        "affected": "<1.4.2",
                        "severity": "critical",
                        "summary": "Test entry.",
                    }
                ],
            }
        )
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"server": {"name": "acme-mcp-server", "version": "1.0.0"}, "tools": []})
    )
    code = main(["scan", str(manifest_path), "--cve-feed", str(feed_path), "--format", "json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    ids = {f["check_id"] for f in payload["findings"]}
    assert "known_vulnerable_package" in ids
    assert code == 1  # critical finding fails the default high gate


def test_cli_scan_missing_feed_file_is_a_clean_error(tmp_path, capsys):
    from mcp_audit.cli import main

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"server": {"name": "x"}, "tools": []}))
    code = main(["scan", str(manifest_path), "--cve-feed", str(tmp_path / "nope.json")])
    err = capsys.readouterr().err
    assert code == 2
    assert "cannot read CVE feed" in err
