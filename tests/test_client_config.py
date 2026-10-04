"""Tests for the MCP client-config scanner.

Covers config normalization plus each config_* check against focused
fixtures, and the scan-config CLI path end to end.
"""

import json

import pytest

from mcp_audit import audit_server
from mcp_audit.cli import main as cli_main
from mcp_audit.client_config import normalize_servers, scan_client_config

RISKY_CONFIG = {
    "mcpServers": {
        "unpinned-pkg": {
            "command": "npx",
            "args": ["-y", "some-mcp-server"],
        },
        "pinned-pkg": {
            "command": "uvx",
            "args": ["some-server@1.2.3"],
        },
        "leaky-env": {
            "command": "/usr/local/bin/server",
            "env": {"MY_API_KEY": "sk-live-abc", "DEBUG": "1"},
        },
        "open-remote": {
            "url": "http://mcp.example.com/sse",
        },
        "authed-remote": {
            "url": "https://mcp.example.com/sse",
            "headers": {"Authorization": "Bearer abc"},
        },
        "localhost-dev": {
            "url": "http://127.0.0.1:8080/mcp",
        },
        "pipe-install": {
            "command": "sh",
            "args": ["-c", "curl https://example.com/install.sh | sh"],
        },
    }
}


def _scan(config):
    manifest = {
        "server": {"name": "client-config"},
        "client_servers": normalize_servers(config, "test"),
    }
    return audit_server(manifest)


def _by_target(report, check_id):
    return [f for f in report.findings if f.check_id == check_id]


def test_normalize_stdio_and_http():
    servers = normalize_servers(RISKY_CONFIG, "cursor")
    by_name = {s["name"]: s for s in servers}
    assert by_name["unpinned-pkg"]["transport"] == "stdio"
    assert by_name["unpinned-pkg"]["args"] == ["-y", "some-mcp-server"]
    assert by_name["open-remote"]["transport"] == "http"
    assert by_name["open-remote"]["url"] == "http://mcp.example.com/sse"
    assert all(s["source"] == "cursor" for s in servers)


def test_remote_package_unpinned_fires():
    report = _scan(RISKY_CONFIG)
    findings = _by_target(report, "config_remote_package")
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].target == "server:unpinned-pkg"
    assert "some-mcp-server" in findings[0].explanation


def test_remote_package_pinned_silent():
    report = _scan(RISKY_CONFIG)
    targets = [f.target for f in _by_target(report, "config_remote_package")]
    assert "server:pinned-pkg" not in targets


def test_plaintext_secret_fires():
    report = _scan(RISKY_CONFIG)
    findings = _by_target(report, "config_plaintext_secret")
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].target == "server:leaky-env"
    assert "MY_API_KEY" in findings[0].explanation


def test_unauthenticated_http_remote_is_high():
    report = _scan(RISKY_CONFIG)
    findings = _by_target(report, "config_unauthenticated_http")
    by_target = {f.target: f for f in findings}
    assert by_target["server:open-remote"].severity == "high"
    assert by_target["server:localhost-dev"].severity == "medium"
    assert "server:authed-remote" not in by_target


def test_insecure_transport_fires_only_off_localhost():
    report = _scan(RISKY_CONFIG)
    findings = _by_target(report, "config_insecure_transport")
    assert [f.target for f in findings] == ["server:open-remote"]
    assert findings[0].severity == "high"


def test_shell_pipe_fires():
    report = _scan(RISKY_CONFIG)
    findings = _by_target(report, "config_shell_pipe")
    assert len(findings) == 1
    assert findings[0].target == "server:pipe-install"
    assert findings[0].severity == "high"


def test_clean_config_is_silent():
    config = {
        "mcpServers": {
            "local": {
                "command": "/usr/local/bin/server",
                "args": ["--port", "9001"],
                "env": {"LOG_LEVEL": "info"},
            },
            "remote": {
                "url": "https://mcp.example.com/sse",
                "headers": {"Authorization": "Bearer abc"},
            },
        }
    }
    report = _scan(config)
    assert report.findings == []


def test_scan_client_config_reads_file(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(RISKY_CONFIG))
    report = scan_client_config(path)
    assert report.manifest_name == "client-config:mcp.json"
    ids = {f.check_id for f in report.findings}
    assert {
        "config_remote_package",
        "config_plaintext_secret",
        "config_unauthenticated_http",
        "config_insecure_transport",
        "config_shell_pipe",
    } <= ids
    for finding in report.findings:
        assert finding.severity_rationale, finding.check_id


def test_scan_client_config_bad_json(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text("{not json")
    with pytest.raises((ValueError, json.JSONDecodeError)):
        scan_client_config(path)


def test_config_checks_silent_on_server_manifests():
    # The config checks must not fire on ordinary server manifests.
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
        }
    )
    ids = {f.check_id for f in report.findings}
    assert not any(i.startswith("config_") for i in ids)


def test_cli_scan_config(tmp_path, capsys):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(RISKY_CONFIG))
    code = cli_main(["scan-config", "--path", str(path)])
    assert code == 1  # high findings fail the default policy
    out = capsys.readouterr().out
    assert "unpinned-pkg" in out


def test_cli_scan_config_clean(tmp_path, capsys):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {}}))
    code = cli_main(["scan-config", "--path", str(path)])
    assert code == 0
