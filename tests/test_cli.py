"""CLI tests: formats, exit codes, and error handling."""

import json

import pytest

from mcp_audit.cli import main

VULN_MANIFEST = {
    "server": {"name": "bad-server"},
    "tools": [
        {
            "name": "run_shell",
            "description": "Run a shell command.",
            "inputSchema": {"properties": {"command": {"type": "string"}}},
        },
    ],
}

CLEAN_MANIFEST = {
    "server": {"name": "good-server"},
    "tools": [
        {
            "name": "server_time",
            "description": "Return the server time.",
            "inputSchema": {"properties": {}},
            "annotations": {"readOnlyHint": True, "rate_limit": "60/min"},
        },
    ],
}


@pytest.fixture()
def vuln_file(tmp_path):
    path = tmp_path / "vuln.json"
    path.write_text(json.dumps(VULN_MANIFEST))
    return str(path)


@pytest.fixture()
def clean_file(tmp_path):
    path = tmp_path / "clean.json"
    path.write_text(json.dumps(CLEAN_MANIFEST))
    return str(path)


def test_scan_table_fails_on_high(vuln_file, capsys):
    assert main(["scan", vuln_file]) == 1
    out = capsys.readouterr().out
    assert "bad-server" in out
    assert "CRITICAL" in out


def test_scan_table_passes_clean(capsys, clean_file):
    assert main(["scan", clean_file]) == 0
    assert "No findings" in capsys.readouterr().out


def test_scan_json_format(vuln_file, capsys):
    assert main(["scan", vuln_file, "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["manifest"] == "bad-server"
    assert any(f["check_id"] == "broad_tool" for f in data["findings"])


def test_scan_sarif_format(vuln_file, capsys):
    assert main(["scan", vuln_file, "--format", "sarif"]) == 1
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "mcp-audit"
    assert sarif["runs"][0]["results"]


def test_scan_markdown_format(vuln_file, capsys):
    assert main(["scan", vuln_file, "--format", "markdown"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("# mcp-audit: bad-server")


def test_fail_on_never_passes(vuln_file):
    assert main(["scan", vuln_file, "--fail-on", "never"]) == 0


def test_fail_on_critical_still_fails_on_critical(vuln_file):
    assert main(["scan", vuln_file, "--fail-on", "critical"]) == 1


def test_config_file_policy(tmp_path, vuln_file):
    config = tmp_path / "policy.json"
    config.write_text(json.dumps({"fail_on": "never"}))
    assert main(["scan", vuln_file, "--config", str(config)]) == 0


def test_missing_manifest_returns_2(capsys):
    assert main(["scan", "/does/not/exist.json"]) == 2
    assert "error" in capsys.readouterr().err


def test_malformed_json_returns_2(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    assert main(["scan", str(path)]) == 2


def test_missing_config_returns_2(vuln_file, capsys):
    assert main(["scan", vuln_file, "--config", "/does/not/exist.json"]) == 2
