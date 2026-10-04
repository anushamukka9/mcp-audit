"""Scan MCP client configs for risky server entries.

Your MCP client config (Claude Desktop, Cursor, Claude Code) is a list
of servers the client launches or connects to on your behalf. A bad
entry there runs attacker code every time the client starts, or sends
your agent's traffic somewhere it should not go. This module reads
those config files, normalizes each server entry, and runs the
config_* checks against them.

Supported format: the ``mcpServers`` map used by Claude Desktop,
Cursor, and ``.mcp.json`` project files:

    {
        "mcpServers": {
            "my-server": {
                "command": "npx",
                "args": ["-y", "my-server@1.2.3"],
                "env": {"API_KEY": "..."}
            },
            "remote": {
                "url": "https://mcp.example.com/sse",
                "headers": {"Authorization": "Bearer ..."}
            }
        }
    }

Claude Code's ``~/.claude.json`` is read when it carries a top-level
``mcpServers`` map; older layouts that nest the map elsewhere are
skipped with a note, not guessed at.

Default search locations:
- Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json
  (macOS), %APPDATA%/Claude/claude_desktop_config.json (Windows),
  ~/.config/Claude/claude_desktop_config.json (Linux)
- Cursor: ~/.cursor/mcp.json
- Claude Code: ~/.claude.json

Everything is local file reads. Nothing is sent anywhere.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import audit_server
from .core import AuditReport
from .policy import AuditPolicy


def default_config_paths() -> list[tuple[str, Path]]:
    """(source label, path) pairs to search, in priority order."""
    home = Path.home()
    desktop: Path
    if sys.platform == "darwin":
        desktop = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        desktop = Path(appdata) / "Claude" / "claude_desktop_config.json"
    else:
        desktop = home / ".config" / "Claude" / "claude_desktop_config.json"
    return [
        ("claude-desktop", desktop),
        ("cursor", home / ".cursor" / "mcp.json"),
        ("claude-code", home / ".claude.json"),
    ]


def load_config_file(path: str | Path) -> dict:
    """Read and parse one config file. Raises ValueError on bad input."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: config must be a JSON object")
    return data


def normalize_servers(config: dict, source: str) -> list[dict]:
    """Turn a config's mcpServers map into the client_servers list.

    Each entry becomes::

        {"name": ..., "source": ..., "transport": "stdio"|"http",
         "command": ..., "args": [...], "env": {...},
         "url": ..., "headers": {...}}

    Entries that are neither stdio (command) nor remote (url) are kept
    with transport "unknown" so the checks can ignore them loudly rather
    than silently.
    """
    servers = config.get("mcpServers", {}) or {}
    if not isinstance(servers, dict):
        raise ValueError(f"{source}: mcpServers must be an object")
    normalized = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        item: dict = {"name": str(name), "source": source}
        if entry.get("command"):
            item["transport"] = "stdio"
            item["command"] = str(entry.get("command") or "")
            item["args"] = [str(a) for a in (entry.get("args") or [])]
            env = entry.get("env") or {}
            item["env"] = {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {}
        elif entry.get("url"):
            item["transport"] = str(entry.get("transport") or "http")
            item["url"] = str(entry.get("url") or "")
            headers = entry.get("headers") or {}
            item["headers"] = (
                {str(k): str(v) for k, v in headers.items()} if isinstance(headers, dict) else {}
            )
        else:
            item["transport"] = "unknown"
        normalized.append(item)
    return normalized


def scan_client_config(
    path: str | Path,
    checks: list | None = None,
    policy: AuditPolicy | None = None,
) -> AuditReport:
    """Scan one client config file. Returns an AuditReport."""
    config = load_config_file(path)
    source = Path(path).name
    servers = normalize_servers(config, source)
    manifest = {
        "server": {"name": f"client-config:{source}"},
        "client_servers": servers,
    }
    return audit_server(manifest, checks=checks, policy=policy)


def scan_discovered_configs(
    checks: list | None = None,
    policy: AuditPolicy | None = None,
) -> list[tuple[str, Path, AuditReport]]:
    """Scan every default config file that exists. Returns (source, path, report)."""
    results = []
    for source, path in default_config_paths():
        if path.is_file():
            results.append((source, path, scan_client_config(path, checks, policy)))
    return results
