"""Live-server audit mode: enumerate a running MCP server and audit it.

Static manifests describe what a server *should* expose. A live audit
asks the server itself: it connects over HTTP (streamable or legacy
SSE) or stdio, runs the MCP initialize handshake, calls tools/list,
resources/list, and prompts/list, and builds the manifest from the
answers. Then it runs the full default check suite against that
manifest, plus the live-transport checks, which read the measured
``transport`` block:

    "transport": {
        "type": "http",            # "http" | "sse" | "stdio"
        "url": "http://0.0.0.0:8080/mcp",
        "bind": "0.0.0.0",         # declared via --bind; a probe cannot
                                   # see a bind address from outside
        "port": 8080,
        "auth_required": false,     # measured by the probe
        "probed": true,
        "server_name": "my-server"
    }

The auth value is measured, not declared. The probe tries an
unauthenticated initialize + tools/list first: if the server answers,
``auth_required`` is False and the unauthenticated_exposure check fires
at critical. If the server returns 401/403, ``auth_required`` is True
and enumeration continues with the caller's ``--header`` credentials if
given.

Everything here uses the standard library only (urllib, subprocess),
same as the rest of mcp-audit. No third-party MCP SDK needed: the
client speaks just enough JSON-RPC to enumerate a server.

Limitations, stated plainly:
- The probe exercises initialize, tools/list, resources/list, and
  prompts/list. It never calls a tool, so tools/call auth is untested.
- A server can require auth on some methods but not others; the probe
  only reports what it tried.
- The bind address is always declared (``--bind``), never measured.
- Legacy SSE and streamable HTTP are both supported; exotic transports
  (WebSocket, custom) are not.
"""

from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import audit_server
from .core import AuditReport
from .policy import AuditPolicy

PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "mcp-audit", "version": "0.5.0"}
_DEFAULT_TIMEOUT = 10.0


class LiveAuditError(Exception):
    """The live audit could not reach or enumerate the server."""


class _McpError(Exception):
    """The server answered with a JSON-RPC error."""


class _HttpAuthError(_McpError):
    """The server answered 401/403: authentication is required."""


class _HttpStatusError(LiveAuditError):
    """The server answered with a non-2xx, non-auth HTTP status."""

    def __init__(self, url: str, code: int, detail: str = ""):
        super().__init__(f"POST {url} failed with HTTP {code}: {detail}")
        self.url = url
        self.code = code


def _rpc_request(req_id: int, method: str, params: dict | None) -> dict:
    msg: dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _rpc_notification(method: str, params: dict | None) -> dict:
    msg: dict = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _parse_sse_body(body: str, want_id: int | None) -> dict | None:
    """Find the JSON-RPC message with want_id in an SSE stream body."""
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            continue
        try:
            msg = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if want_id is None or msg.get("id") == want_id:
            return msg
    return None


class _HttpSession:
    """One MCP-over-HTTP session: streamable POST or legacy SSE."""

    def __init__(self, url: str, headers: dict[str, str], timeout: float):
        self.url = url
        self.headers = dict(headers or {})
        self.timeout = timeout
        self._next_id = 0
        self._session_id: str | None = None
        self.mode = "http"  # or "sse" after legacy-SSE fallback
        self._message_url = url

    def _base_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "User-Agent": f"mcp-audit/{CLIENT_INFO['version']}",
        }
        headers.update(self.headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    def _post(self, url: str, payload: dict) -> tuple[int, str, dict]:
        data = json.dumps(payload).encode("utf-8")
        headers = self._base_headers()
        headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                resp_headers = dict(resp.headers.items())
                session_id = resp_headers.get("Mcp-Session-Id")
                if session_id:
                    self._session_id = session_id
                return resp.status, body, resp_headers
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise _HttpAuthError(f"server returned {exc.code}") from exc
            detail = exc.read().decode("utf-8", errors="replace")[:200]
            raise _HttpStatusError(url, exc.code, detail) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LiveAuditError(f"could not reach {url}: {exc}") from exc

    def _discover_sse_endpoint(self) -> str:
        """Legacy SSE transport: GET the URL, read the endpoint event."""
        req = urllib.request.Request(
            self.url,
            headers={
                "Accept": "text/event-stream",
                "User-Agent": f"mcp-audit/{CLIENT_INFO['version']}",
                **self.headers,
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                deadline = time.monotonic() + self.timeout
                event_name = ""
                while time.monotonic() < deadline:
                    raw = resp.readline()
                    if not raw:
                        break  # server closed the stream
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        event_name = ""
                        continue
                    if line.startswith("event:"):
                        event_name = line[6:].strip()
                    elif line.startswith("data:"):
                        data = line[5:].strip()
                        if event_name == "endpoint" and data:
                            return urllib.parse.urljoin(self.url, data)
                        event_name = ""
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise _HttpAuthError(f"server returned {exc.code}") from exc
            raise LiveAuditError(f"SSE handshake failed: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LiveAuditError(f"could not reach {self.url}: {exc}") from exc
        raise LiveAuditError("SSE handshake gave no endpoint event")

    def initialize(self) -> dict:
        """Run the MCP initialize handshake. Returns the server's result."""
        self._next_id += 1
        req_id = self._next_id
        payload = _rpc_request(
            req_id,
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        try:
            _status, body, headers = self._post(self.url, payload)
        except (_HttpStatusError, _HttpAuthError) as exc:
            if isinstance(exc, _HttpStatusError) and exc.code not in (
                404,
                405,
                400,
                501,
            ):
                raise
            # Either a legacy SSE server that does not take POST here, or a
            # server that 401s the streamable POST. The SSE handshake carries
            # the same headers, so auth still works through this path.
            self.mode = "sse"
            self._message_url = self._discover_sse_endpoint()
            _status, body, headers = self._post(self._message_url, payload)
        content_type = headers.get("Content-Type", "")
        if "text/event-stream" in content_type:
            msg = _parse_sse_body(body, req_id)
        else:
            try:
                msg = json.loads(body) if body.strip() else None
            except json.JSONDecodeError as exc:
                raise LiveAuditError(f"server returned non-JSON: {body[:200]}") from exc
        if not msg or msg.get("id") != req_id:
            raise LiveAuditError("initialize got no usable response")
        if "error" in msg:
            raise _McpError(f"initialize failed: {msg['error']}")
        result = msg.get("result", {})
        # Tell the server we are ready; some servers require this.
        try:
            self.notify("notifications/initialized")
        except LiveAuditError:
            pass
        return result

    def call(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        req_id = self._next_id
        _status, body, headers = self._post(
            self._message_url, _rpc_request(req_id, method, params or {})
        )
        content_type = headers.get("Content-Type", "")
        if "text/event-stream" in content_type:
            msg = _parse_sse_body(body, req_id)
        else:
            try:
                msg = json.loads(body) if body.strip() else None
            except json.JSONDecodeError as exc:
                raise LiveAuditError(f"server returned non-JSON: {body[:200]}") from exc
        if not msg or msg.get("id") != req_id:
            raise LiveAuditError(f"{method} got no usable response")
        if "error" in msg:
            err = msg["error"]
            if isinstance(err, dict) and err.get("code") == -32601:
                raise _McpError(f"method not found: {method}")
            raise _McpError(f"{method} failed: {err}")
        return msg.get("result", {})

    def notify(self, method: str, params: dict | None = None) -> None:
        self._post(self._message_url, _rpc_notification(method, params or {}))

    def close(self) -> None:
        pass


class _StdioSession:
    """One MCP-over-stdio session: newline-delimited JSON-RPC on pipes."""

    def __init__(self, command: list[str], env: dict[str, str] | None, timeout: float):
        self.timeout = timeout
        self._next_id = 0
        merged = dict(os.environ)
        merged.update(env or {})
        try:
            self.proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                env=merged,
            )
        except OSError as exc:
            raise LiveAuditError(f"could not launch {' '.join(command)}: {exc}") from exc
        self._lines: queue.Queue[str] = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        try:
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                line = line.strip()
                if line:
                    self._lines.put(line)
        except Exception:
            pass

    def initialize(self) -> dict:
        """Run the MCP initialize handshake. Returns the server's result."""
        result = self.call(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        try:
            self.notify("notifications/initialized")
        except LiveAuditError:
            pass
        return result

    def _send(self, payload: dict) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise LiveAuditError("stdio server closed the pipe") from exc

    def call(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        req_id = self._next_id
        self._send(_rpc_request(req_id, method, params or {}))
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LiveAuditError(f"stdio server timed out on {method}")
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty as exc:
                raise LiveAuditError(f"stdio server timed out on {method}") from exc
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict) or msg.get("id") != req_id:
                continue
            if "error" in msg:
                err = msg["error"]
                if isinstance(err, dict) and err.get("code") == -32601:
                    raise _McpError(f"method not found: {method}")
                raise _McpError(f"{method} failed: {err}")
            return msg.get("result", {})

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send(_rpc_notification(method, params or {}))

    def close(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def _enumerate(session: _HttpSession | _StdioSession) -> tuple[dict, list, list, list]:
    """Handshake, then pull tools/resources/prompts. Missing methods -> []."""
    init = session.initialize()
    try:
        session.notify("notifications/initialized")
    except (LiveAuditError, _McpError):
        pass

    def safe_list(method: str, key: str) -> list:
        try:
            result = session.call(method, {})
        except _McpError:
            return []
        items = result.get(key, [])
        return items if isinstance(items, list) else []

    tools = safe_list("tools/list", "tools")
    resources = safe_list("resources/list", "resources")
    prompts = safe_list("prompts/list", "prompts")
    return init, tools, resources, prompts


def _port_of(url: str) -> int | None:
    try:
        return urllib.parse.urlsplit(url).port
    except ValueError:
        return None


@dataclass
class LiveTarget:
    """Everything live_audit needs to reach one server."""

    url: str | None = None
    command: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    bind: str | None = None
    timeout: float = _DEFAULT_TIMEOUT


def live_audit(
    target: LiveTarget,
    checks: list | None = None,
    policy: AuditPolicy | None = None,
) -> AuditReport:
    """Audit a running MCP server. Returns an AuditReport.

    Exactly one of target.url / target.command must be set. The report's
    manifest carries a measured "transport" block, which the
    live-transport checks (unauthenticated_exposure, exposed_bind,
    dangerous_default_port, network_tool_bridge) read.
    """
    if bool(target.url) == bool(target.command):
        raise LiveAuditError("set exactly one of url or command")

    auth_required: bool | None = None
    server_name = "live-server"
    transport: dict = {}

    if target.url:
        url = target.url
        # Probe 1: unauthenticated. If the server answers, the exposure is
        # measured, not declared.
        session: _HttpSession | _StdioSession = _HttpSession(url, {}, target.timeout)
        try:
            init, tools, resources, prompts = _enumerate(session)
            auth_required = False
        except _HttpAuthError:
            auth_required = True
            session.close()
            if not target.headers:
                raise LiveAuditError(
                    "the server requires authentication (401/403 on an "
                    "unauthenticated probe). Re-run with --header "
                    "'Authorization: Bearer <token>' to enumerate it."
                ) from None
            session = _HttpSession(url, target.headers, target.timeout)
            try:
                init, tools, resources, prompts = _enumerate(session)
            except _HttpAuthError as exc:
                raise LiveAuditError("the server rejected the provided credentials too.") from exc
        finally:
            session.close()
        server_name = (init.get("serverInfo", {}) or {}).get("name") or "live-server"
        transport = {
            "type": getattr(session, "mode", "http"),
            "url": url,
            "port": _port_of(url),
            "auth_required": auth_required,
            "probed": True,
        }
        if target.bind:
            transport["bind"] = target.bind
    else:
        session = _StdioSession(target.command, target.env, target.timeout)
        try:
            init, tools, resources, prompts = _enumerate(session)
        finally:
            session.close()
        server_name = (init.get("serverInfo", {}) or {}).get("name") or "live-server"
        transport = {"type": "stdio", "probed": True}

    manifest = {
        "server": {"name": server_name, "transport": transport},
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
    }
    return audit_server(manifest, checks=checks, policy=policy)


def parse_command(command: str) -> list[str]:
    """Split a shell-style command string for stdio launch."""
    return shlex.split(command)


def parse_headers(header_args: list[str]) -> dict[str, str]:
    """Parse ['Name: Value', ...] into a headers dict."""
    headers: dict[str, str] = {}
    for item in header_args:
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise LiveAuditError(f"bad --header {item!r}; use 'Name: Value'")
        headers[name.strip()] = value.strip()
    return headers


def parse_env(env_args: list[str]) -> dict[str, str]:
    """Parse ['KEY=VAL', ...] into an env dict."""
    env: dict[str, str] = {}
    for item in env_args:
        key, sep, value = item.partition("=")
        if not sep or not key.strip():
            raise LiveAuditError(f"bad --env {item!r}; use 'KEY=VALUE'")
        env[key.strip()] = value
    return env
