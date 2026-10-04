"""Unit tests for the four live-transport checks.

These checks read the measured/declared "transport" block on
manifest["server"]. No network involved: the transport dict is built by
hand, exactly as mcp_audit.live builds it from a real probe.
"""

from mcp_audit import audit_server
from mcp_audit.checks import check_by_id


def _manifest(transport, tools=None):
    return {
        "server": {"name": "s", "transport": transport},
        "tools": tools or [],
    }


def _findings(check_id, manifest):
    check = check_by_id(check_id)
    assert check is not None
    return check.run(manifest)


SHELL_TOOL = {
    "name": "run_shell",
    "description": "Run a shell command.",
    "inputSchema": {"properties": {"command": {"type": "string"}}},
}
READONLY_TOOL = {
    "name": "server_time",
    "description": "Return the server time.",
    "inputSchema": {"properties": {}},
    "annotations": {"readOnlyHint": True},
}


def test_unauthenticated_exposure_measured_is_critical():
    findings = _findings(
        "unauthenticated_exposure",
        _manifest(
            {
                "type": "http",
                "url": "http://0.0.0.0:8080/mcp",
                "auth_required": False,
                "probed": True,
            }
        ),
    )
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].severity_rationale


def test_unauthenticated_exposure_declared_is_high():
    findings = _findings(
        "unauthenticated_exposure",
        _manifest(
            {
                "type": "http",
                "url": "http://0.0.0.0:8080/mcp",
                "auth_required": False,
                "probed": False,
            }
        ),
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_unauthenticated_exposure_silent_when_auth_required():
    findings = _findings(
        "unauthenticated_exposure",
        _manifest({"type": "http", "auth_required": True, "probed": True}),
    )
    assert findings == []


def test_unauthenticated_exposure_silent_without_transport():
    assert _findings("unauthenticated_exposure", {"server": {"name": "s"}}) == []
    # stdio has no network exposure to measure
    assert (
        _findings(
            "unauthenticated_exposure",
            _manifest({"type": "stdio", "probed": True}),
        )
        == []
    )


def test_exposed_bind_wide():
    for bind in ("0.0.0.0", "::", "[::]"):
        findings = _findings(
            "exposed_bind",
            _manifest({"type": "http", "bind": bind, "port": 8080}),
        )
        assert len(findings) == 1, bind
        assert findings[0].severity == "high"


def test_exposed_bind_loopback_silent():
    findings = _findings(
        "exposed_bind",
        _manifest({"type": "http", "bind": "127.0.0.1", "port": 8080}),
    )
    assert findings == []


def test_exposed_bind_undeclared_silent():
    # A probe cannot see the bind address; without a declaration the check
    # stays silent rather than guessing.
    findings = _findings(
        "exposed_bind",
        _manifest({"type": "http", "url": "http://0.0.0.0:8080/mcp", "probed": True}),
    )
    assert findings == []


def test_dangerous_default_port():
    for port in (3000, 5000, 8000, 8080, 9000, 6274, 6277):
        findings = _findings(
            "dangerous_default_port",
            _manifest({"type": "http", "port": port}),
        )
        assert len(findings) == 1, port
        assert findings[0].severity == "low"


def test_dangerous_default_port_uncommon_silent():
    findings = _findings(
        "dangerous_default_port",
        _manifest({"type": "http", "port": 18765}),
    )
    assert findings == []


def test_dangerous_default_port_stdio_silent():
    findings = _findings(
        "dangerous_default_port",
        _manifest({"type": "stdio"}),
    )
    assert findings == []


def test_network_tool_bridge_wide_bind_shell():
    findings = _findings(
        "network_tool_bridge",
        _manifest(
            {"type": "http", "bind": "0.0.0.0", "port": 8080},
            tools=[SHELL_TOOL],
        ),
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "run_shell" in findings[0].explanation


def test_network_tool_bridge_loopback_silent():
    findings = _findings(
        "network_tool_bridge",
        _manifest(
            {"type": "http", "bind": "127.0.0.1", "port": 8080},
            tools=[SHELL_TOOL],
        ),
    )
    assert findings == []


def test_network_tool_bridge_no_privileged_tools_silent():
    findings = _findings(
        "network_tool_bridge",
        _manifest(
            {"type": "http", "bind": "0.0.0.0", "port": 8080},
            tools=[READONLY_TOOL],
        ),
    )
    assert findings == []


def test_network_tool_bridge_non_loopback_url_without_bind():
    findings = _findings(
        "network_tool_bridge",
        _manifest(
            {"type": "http", "url": "http://192.168.1.5:8080/mcp", "port": 8080},
            tools=[SHELL_TOOL],
        ),
    )
    assert len(findings) == 1


def test_live_checks_run_through_audit_server():
    report = audit_server(
        _manifest(
            {
                "type": "http",
                "url": "http://0.0.0.0:8080/mcp",
                "bind": "0.0.0.0",
                "port": 8080,
                "auth_required": False,
                "probed": True,
            },
            tools=[SHELL_TOOL],
        )
    )
    ids = {f.check_id for f in report.findings}
    assert {
        "unauthenticated_exposure",
        "exposed_bind",
        "dangerous_default_port",
        "network_tool_bridge",
    } <= ids
    for finding in report.findings:
        assert finding.severity_rationale, finding.check_id
