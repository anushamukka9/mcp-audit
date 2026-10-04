"""Integration tests for live-server audit mode.

A fake MCP server runs in a thread (streamable HTTP on /mcp, legacy SSE
handshake on /sse). The tests exercise the real probe path: the
unauthenticated tools/list probe, the 401 retry with credentials, SSE
endpoint discovery, and stdio launch. No external network, no mocks of
the client itself.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mcp_audit.cli import main as cli_main
from mcp_audit.live import (
    LiveAuditError,
    LiveTarget,
    live_audit,
    parse_env,
    parse_headers,
)

SHELL_TOOL = {
    "name": "run_shell",
    "description": "Run a shell command.",
    "inputSchema": {"properties": {"command": {"type": "string"}}},
}

FAKE_SERVER_SCRIPT = """\
import json
import sys


def reply(req_id, result):
    sys.stdout.write(
        json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\\n"
    )
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    req_id = msg.get("id")
    if req_id is None:
        continue  # notification
    method = msg.get("method")
    if method == "initialize":
        reply(
            req_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "fake-stdio", "version": "0.1.0"},
            },
        )
    elif method == "tools/list":
        reply(
            req_id,
            {
                "tools": [
                    {
                        "name": "run_shell",
                        "description": "Run a shell command.",
                        "inputSchema": {
                            "properties": {"command": {"type": "string"}}
                        },
                    }
                ]
            },
        )
    elif method in ("resources/list", "prompts/list"):
        key = "resources" if method == "resources/list" else "prompts"
        reply(req_id, {key: []})
    else:
        sys.stdout.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            )
            + "\\n"
        )
        sys.stdout.flush()
"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self):
        if getattr(self.server, "require_auth", False):
            if self.headers.get("Authorization") != "Bearer test-token":
                body = b"unauthorized"
                self.send_response(401)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return False
        return True

    def _handle_rpc(self, msg):
        method = msg.get("method")
        req_id = msg.get("id")
        if req_id is None:  # notification
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "fake-mcp", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": [dict(SHELL_TOOL)]}
        elif method == "resources/list":
            result = {"resources": []}
        elif method == "prompts/list":
            result = {"prompts": []}
        else:
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            )
            return
        self._send_json({"jsonrpc": "2.0", "id": req_id, "result": result})

    def do_POST(self):
        if self.path == "/sse" or self.path == "/":
            # Legacy SSE servers do not take POST on the event URL.
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if not self._check_auth():
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            msg = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._handle_rpc(msg)

    def do_GET(self):
        if not self._check_auth():
            return
        if self.path == "/sse":
            body = b"event: endpoint\ndata: /messages?sessionId=test123\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


def _serve(require_auth=False):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.require_auth = require_auth
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture()
def open_server():
    server = _serve(require_auth=False)
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture()
def auth_server():
    server = _serve(require_auth=True)
    yield server
    server.shutdown()
    server.server_close()


def _url(server, path="/mcp"):
    return f"http://127.0.0.1:{server.server_address[1]}{path}"


def test_live_audit_http_unauthenticated(open_server):
    report = live_audit(LiveTarget(url=_url(open_server), timeout=5.0))
    assert report.manifest_name == "fake-mcp"
    by_id = {f.check_id: f for f in report.findings}
    exposure = by_id["unauthenticated_exposure"]
    assert exposure.severity == "critical"
    assert "unauthenticated" in exposure.explanation
    # The live surface runs the full static suite too.
    assert "broad_tool" in by_id


def test_live_audit_measures_transport_block(open_server):
    report = live_audit(LiveTarget(url=_url(open_server), timeout=5.0))
    transport = next(f for f in report.findings if f.check_id == "unauthenticated_exposure")
    assert transport.target == "server:fake-mcp"


def test_live_audit_auth_required_without_creds(auth_server):
    with pytest.raises(LiveAuditError, match="requires authentication"):
        live_audit(LiveTarget(url=_url(auth_server), timeout=5.0))


def test_live_audit_auth_required_with_creds(auth_server):
    target = LiveTarget(
        url=_url(auth_server),
        headers={"Authorization": "Bearer test-token"},
        timeout=5.0,
    )
    report = live_audit(target)
    assert report.manifest_name == "fake-mcp"
    ids = {f.check_id for f in report.findings}
    assert "unauthenticated_exposure" not in ids
    assert "broad_tool" in ids


def test_live_audit_wrong_creds_still_fails(auth_server):
    target = LiveTarget(
        url=_url(auth_server),
        headers={"Authorization": "Bearer wrong"},
        timeout=5.0,
    )
    with pytest.raises(LiveAuditError):
        live_audit(target)


def test_live_audit_legacy_sse(open_server):
    report = live_audit(LiveTarget(url=_url(open_server, "/sse"), timeout=5.0))
    assert report.manifest_name == "fake-mcp"
    assert "broad_tool" in {f.check_id for f in report.findings}


def test_live_audit_stdio(tmp_path):
    script = tmp_path / "fake_server.py"
    script.write_text(FAKE_SERVER_SCRIPT)
    target = LiveTarget(command=[sys.executable, str(script)], timeout=5.0)
    report = live_audit(target)
    assert report.manifest_name == "fake-stdio"
    ids = {f.check_id for f in report.findings}
    assert "broad_tool" in ids
    # stdio has no network transport: none of the live checks fire.
    assert "unauthenticated_exposure" not in ids
    assert "exposed_bind" not in ids
    assert "network_tool_bridge" not in ids


def test_live_audit_needs_exactly_one_target():
    with pytest.raises(LiveAuditError, match="exactly one"):
        live_audit(LiveTarget())
    with pytest.raises(LiveAuditError, match="exactly one"):
        live_audit(LiveTarget(url="http://x/", command=["y"]))


def test_live_audit_bind_flag_declares_exposure(open_server):
    target = LiveTarget(url=_url(open_server), bind="0.0.0.0", timeout=5.0)
    report = live_audit(target)
    by_id = {f.check_id: f for f in report.findings}
    assert by_id["exposed_bind"].severity == "high"


def test_live_audit_unreachable_host():
    with pytest.raises(LiveAuditError, match="could not reach"):
        live_audit(LiveTarget(url="http://127.0.0.1:9/mcp", timeout=2.0))


def test_cli_live_against_open_server(open_server, capsys):
    code = cli_main(["live", "--url", _url(open_server)])
    assert code == 1  # critical unauthenticated_exposure fails the default policy
    out = capsys.readouterr().out
    assert "fake-mcp" in out
    assert "unauthenticated" in out.lower()


def test_cli_live_bad_url_is_exit_2(capsys):
    code = cli_main(["live", "--url", "http://127.0.0.1:9/mcp", "--timeout", "1"])
    assert code == 2
    assert "live audit failed" in capsys.readouterr().err


def test_parse_headers():
    assert parse_headers(["Authorization: Bearer x", "X-Api-Key:abc"]) == {
        "Authorization": "Bearer x",
        "X-Api-Key": "abc",
    }
    with pytest.raises(LiveAuditError):
        parse_headers(["no-colon"])


def test_parse_env():
    assert parse_env(["A=1", "B=x=y"]) == {"A": "1", "B": "x=y"}
    with pytest.raises(LiveAuditError):
        parse_env(["NOEQUALS"])
