"""Scan MCP client configs for risky server entries.

Your MCP client config (Claude Desktop, Cursor, Windsurf, Claude Code)
is a list of servers the client launches or connects to on your behalf.
A bad entry there runs attacker code every time the client starts, or
sends your agent's traffic somewhere it should not go. This module
reads those config files, normalizes each server entry, and runs the
config_* checks against them.

Supported format: the ``mcpServers`` map used by Claude Desktop,
Cursor, Windsurf, and ``.mcp.json`` project files:

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

Two spelling differences in the wild, both handled:

- Windsurf writes the remote URL as ``serverUrl``, not ``url`` (it
  also accepts ``url``, and some tools emit ``httpUrl``). A remote
  entry copied from a Windsurf config into a scanner that only knows
  ``url`` would look like an entry with no transport at all, and every
  remote check would stay silent on it. All three spellings normalize
  to the same remote entry here.
- Cursor and Windsurf often spell the transport as ``type`` (``sse``,
  ``streamable-http``) instead of ``transport``. ``streamable-http``
  normalizes to ``http`` so the remote checks recognize it.

Claude Code's ``~/.claude.json`` is read when it carries a top-level
``mcpServers`` map; older layouts that nest the map elsewhere are
skipped with a note, not guessed at.

An entry marked ``"disabled": true`` is still scanned. Disabling is
one click in the client UI, and a plaintext secret in the file is in
the file whether the server currently runs or not. The flag is kept
on the normalized entry so reports can show it.

Default search locations:
- Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json
  (macOS), %APPDATA%/Claude/claude_desktop_config.json (Windows),
  ~/.config/Claude/claude_desktop_config.json (Linux)
- Cursor (global): ~/.cursor/mcp.json
- Cursor (project): .cursor/mcp.json in the current directory
- Windsurf: ~/.codeium/windsurf/mcp_config.json
- Windsurf, as Devin Desktop: ~/.config/devin/mcp_config.json
  (macOS and Linux), %APPDATA%/devin/mcp_config.json (Windows)
- Claude Code: ~/.claude.json
- Claude Code (project): .mcp.json in the current directory

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

_REMOTE_URL_KEYS = ("url", "serverUrl", "httpUrl")

_TRANSPORT_ALIASES = {
    "http": "http",
    "streamable-http": "http",
    "streamable_http": "http",
    "streamablehttp": "http",
    "sse": "sse",
}


def _remote_transport(entry: dict) -> str:
    raw = str(entry.get("transport") or entry.get("type") or "http").lower()
    return _TRANSPORT_ALIASES.get(raw, "http")


def _string_map(value: object) -> dict:
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    return {}


def default_config_paths() -> list[tuple[str, Path]]:
    """(source label, path) pairs to search, in priority order."""
    home = Path.home()
    cwd = Path.cwd()
    desktop: Path
    devin: Path
    if sys.platform == "darwin":
        desktop = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        devin = home / ".config" / "devin" / "mcp_config.json"
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        desktop = Path(appdata) / "Claude" / "claude_desktop_config.json"
        devin = Path(appdata) / "devin" / "mcp_config.json"
    else:
        desktop = home / ".config" / "Claude" / "claude_desktop_config.json"
        devin = home / ".config" / "devin" / "mcp_config.json"
    return [
        ("claude-desktop", desktop),
        ("cursor", home / ".cursor" / "mcp.json"),
        ("cursor-project", cwd / ".cursor" / "mcp.json"),
        ("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("windsurf-devin", devin),
        ("claude-code", home / ".claude.json"),
        ("claude-code-project", cwd / ".mcp.json"),
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

        {"name": ..., "source": ..., "transport": "stdio"|"http"|"sse",
         "command": ..., "args": [...], "env": {...},
         "url": ..., "headers": {...}}

    The remote URL may be spelled ``url``, ``serverUrl`` (Windsurf),
    or ``httpUrl``; all three land in ``url``. The transport may be
    spelled ``transport`` or ``type``; ``streamable-http`` lands as
    ``http``. ``env`` and ``headers`` are kept on both stdio and
    remote entries, because a remote entry can carry a plaintext
    secret in its env block just as easily as a stdio one can.

    Entries that are neither stdio (command) nor remote (any URL
    spelling) are kept with transport "unknown" so the checks can
    ignore them loudly rather than silently.
    """
    servers = config.get("mcpServers", {}) or {}
    if not isinstance(servers, dict):
        raise ValueError(f"{source}: mcpServers must be an object")
    normalized = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        item: dict = {"name": str(name), "source": source}
        if "disabled" in entry:
            item["disabled"] = bool(entry.get("disabled"))
        env = _string_map(entry.get("env"))
        if env:
            item["env"] = env
        headers = _string_map(entry.get("headers"))
        if headers:
            item["headers"] = headers
        remote_url = next((entry.get(key) for key in _REMOTE_URL_KEYS if entry.get(key)), None)
        if entry.get("command"):
            item["transport"] = "stdio"
            item["command"] = str(entry.get("command") or "")
            item["args"] = [str(a) for a in (entry.get("args") or [])]
            item.setdefault("env", {})
        elif remote_url:
            item["transport"] = _remote_transport(entry)
            item["url"] = str(remote_url)
            item.setdefault("headers", {})
        else:
            item["transport"] = "unknown"
        normalized.append(item)
    return normalized


def scan_client_config(
    path: str | Path,
    checks: list | None = None,
    policy: AuditPolicy | None = None,
    source_label: str | None = None,
) -> AuditReport:
    """Scan one client config file. Returns an AuditReport.

    ``source_label`` names the client the file belongs to (for
    example ``windsurf``); it defaults to the file name. The report
    format is the same whatever client wrote the file.
    """
    config = load_config_file(path)
    source = source_label or Path(path).name
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
    """Scan every default config file that exists. Returns (source, path, report).

    If two labels point at the same file (a project config inside the
    home directory, say), the file is scanned once, under the first
    label in priority order.
    """
    results = []
    seen: set[Path] = set()
    for source, path in default_config_paths():
        if not path.is_file():
            continue
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in seen:
            continue
        seen.add(resolved)
        results.append((source, path, scan_client_config(path, checks, policy, source)))
    return results
