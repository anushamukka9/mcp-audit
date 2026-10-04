"""Live-audit a deliberately misconfigured MCP server, end to end.

This spins up a tiny MCP server in a thread that is wrong in exactly
the Ruflo way: it answers tools/list with no authentication, and it
exposes a shell-execution tool. Then it runs mcp_audit.live_audit
against it and prints the report, so you can watch the
unauthenticated_exposure, dangerous_default_port, and
network_tool_bridge checks fire on a real probe.

Safety notes, because this demo is about exposure:
- The demo server binds 127.0.0.1 only. Nothing leaves your machine.
- We pass bind="0.0.0.0" to live_audit to declare how this server *would*
  be deployed in the incident we are modeling. The exposed_bind finding
  is therefore about the declared deployment, and the demo says so.

Usage:
    python examples/live_audit_demo.py [--format table|json|markdown|html]
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from mcp_audit.live import LiveTarget, live_audit  # noqa: E402
from mcp_audit.report import format_report  # noqa: E402

TOOLS = [
    {
        "name": "run_shell",
        "description": "Run a shell command on the host.",
        "inputSchema": {"properties": {"command": {"type": "string"}}},
    },
    {
        "name": "read_file",
        "description": "Read any file from the filesystem.",
        "inputSchema": {"properties": {"path": {"type": "string"}}},
    },
]


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send_json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            msg = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        method, req_id = msg.get("method"), msg.get("id")
        if req_id is None:  # notification
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "demo-exposed-bridge", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method in ("resources/list", "prompts/list"):
            result = {}
        else:
            result = {}
        self._send_json({"jsonrpc": "2.0", "id": req_id, "result": result})


def main(argv: list[str] | None = None) -> int:
    fmt = "table"
    args = list(argv or [])
    if args and args[0] == "--format" and len(args) > 1:
        fmt = args[1]

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # No auth configured on purpose. bind="0.0.0.0" declares the
        # deployment we are modeling; the demo server itself only
        # listens on 127.0.0.1.
        target = LiveTarget(
            url=f"http://127.0.0.1:{port}/mcp",
            bind="0.0.0.0",
            timeout=5.0,
        )
        report = live_audit(target)
    finally:
        server.shutdown()
        server.server_close()

    print(format_report(report, fmt))
    print()
    print(
        "The demo server binds 127.0.0.1 for safety; the exposed_bind "
        "finding above is about the declared 0.0.0.0 deployment."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
