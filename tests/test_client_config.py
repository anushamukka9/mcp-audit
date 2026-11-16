"""Tests for the MCP client-config scanner.

Covers config normalization plus each config_* check against focused
fixtures, and the scan-config CLI path end to end.
"""

import json
from pathlib import Path

import pytest

from mcp_audit import audit_server
from mcp_audit.cli import main as cli_main
from mcp_audit.client_config import (
    default_config_paths,
    normalize_servers,
    scan_client_config,
    scan_discovered_configs,
)

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


# --- Cursor and Windsurf expansion (Nov 16) ---

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "client-configs"

WINDSURF_CONFIG = {
    "mcpServers": {
        "ws-remote": {"serverUrl": "http://mcp.example.com/sse"},
        "ws-authed": {
            "serverUrl": "https://mcp.example.com/mcp",
            "headers": {"Authorization": "Bearer abc"},
        },
        "ws-sse": {"serverUrl": "https://mcp.example.com/sse", "type": "sse"},
        "ws-streamable": {"serverUrl": "https://mcp.example.com/mcp", "type": "streamable-http"},
        "ws-remote-env": {
            "serverUrl": "https://mcp.example.com/mcp",
            "headers": {"Authorization": "Bearer abc"},
            "env": {"REMOTE_API_KEY": "placeholder-value"},
        },
        "ws-disabled": {"serverUrl": "http://mcp.example.com/sse", "disabled": True},
    }
}


def test_windsurf_server_url_normalizes_to_remote():
    servers = normalize_servers(WINDSURF_CONFIG, "windsurf")
    by_name = {s["name"]: s for s in servers}
    assert by_name["ws-remote"]["transport"] == "http"
    assert by_name["ws-remote"]["url"] == "http://mcp.example.com/sse"
    assert by_name["ws-sse"]["transport"] == "sse"
    assert by_name["ws-streamable"]["transport"] == "http"


def test_windsurf_server_url_gets_the_same_checks():
    report = _scan(WINDSURF_CONFIG)
    unauth = {f.target: f for f in _by_target(report, "config_unauthenticated_http")}
    assert unauth["server:ws-remote"].severity == "high"
    assert "server:ws-authed" not in unauth
    insecure = [f.target for f in _by_target(report, "config_insecure_transport")]
    assert "server:ws-remote" in insecure


def test_http_url_spelling_also_normalizes():
    servers = normalize_servers({"mcpServers": {"r": {"httpUrl": "https://x.example/mcp"}}}, "t")
    assert servers[0]["transport"] == "http"
    assert servers[0]["url"] == "https://x.example/mcp"


def test_remote_entry_env_is_kept_and_flagged():
    report = _scan(WINDSURF_CONFIG)
    findings = _by_target(report, "config_plaintext_secret")
    assert [f.target for f in findings] == ["server:ws-remote-env"]


def test_disabled_entry_is_still_scanned():
    servers = normalize_servers(WINDSURF_CONFIG, "windsurf")
    by_name = {s["name"]: s for s in servers}
    assert by_name["ws-disabled"]["disabled"] is True
    report = _scan(WINDSURF_CONFIG)
    targets = [f.target for f in _by_target(report, "config_unauthenticated_http")]
    assert "server:ws-disabled" in targets


def test_default_paths_cover_cursor_and_windsurf():
    labels = {label: path for label, path in default_config_paths()}
    assert labels["cursor"].name == "mcp.json"
    assert labels["cursor-project"].parts[-2:] == (".cursor", "mcp.json")
    assert labels["windsurf"].name == "mcp_config.json"
    assert "windsurf" in str(labels["windsurf"])
    assert labels["windsurf-devin"].name == "mcp_config.json"
    assert "devin" in str(labels["windsurf-devin"])
    assert labels["claude-code-project"].name == ".mcp.json"


def test_scan_discovered_finds_windsurf_under_fake_home(tmp_path, monkeypatch):
    cfg = tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps(WINDSURF_CONFIG))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    found = scan_discovered_configs()
    by_label = {label: report for label, _path, report in found}
    assert "windsurf" in by_label
    ids = {f.check_id for f in by_label["windsurf"].findings}
    assert "config_unauthenticated_http" in ids
    assert by_label["windsurf"].manifest_name == "client-config:windsurf"


def test_scan_client_config_source_label(tmp_path):
    path = tmp_path / "mcp_config.json"
    path.write_text(json.dumps(WINDSURF_CONFIG))
    report = scan_client_config(path, source_label="windsurf")
    assert report.manifest_name == "client-config:windsurf"
    assert all("windsurf" in f.explanation for f in report.findings)


def test_windsurf_fixture_file():
    report = scan_client_config(EXAMPLES / "windsurf_mcp_config.json", source_label="windsurf")
    ids = {f.check_id for f in report.findings}
    assert ids == {
        "config_remote_package",
        "config_plaintext_secret",
        "config_unauthenticated_http",
        "config_insecure_transport",
    }


def test_cursor_project_fixture_file_is_clean():
    report = scan_client_config(EXAMPLES / "cursor_project_mcp.json", source_label="cursor-project")
    assert report.findings == []
