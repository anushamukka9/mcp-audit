"""API tests for the playground backend.

Run from the repo root, with the playground deps installed:

    pip install -e . && pip install -r playground/requirements.txt
    pip install pytest httpx
    python -m pytest playground/tests -q

These tests live outside the library's tests/ on purpose: the main
CI installs only the library's test extra, and the service's web
dependencies should not become the library's problem.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from mcp_audit import audit_server
from playground.app import EXAMPLE_MANIFEST, create_app


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


CLEAN_MANIFEST = {
    "server": {"name": "clean-server", "version": "1.0.0"},
    "tools": [
        {
            "name": "read_doc",
            "description": "Read one document from the docs folder by id.",
            "inputSchema": {
                "type": "object",
                "properties": {"doc_id": {"type": "string", "maxLength": 64}},
                "required": ["doc_id"],
            },
            "annotations": {"readOnlyHint": True, "rate_limit": "60/min"},
        }
    ],
    "resources": [{"name": "guide", "uri": "docs:///guide.md"}],
    "prompts": [],
}


def test_healthz(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_index_describes_the_service(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "mcp-audit playground"
    assert body["checks_run"] > 0
    assert "audit" in body["endpoints"]


def test_example_manifest_is_auditable(client: TestClient) -> None:
    resp = client.get("/example")
    assert resp.status_code == 200
    assert resp.json()["server"]["name"] == "playground-example"


def test_audit_example_matches_the_library(client: TestClient) -> None:
    resp = client.post("/audit", json=EXAMPLE_MANIFEST)
    assert resp.status_code == 200
    body = resp.json()
    direct = audit_server(EXAMPLE_MANIFEST)
    assert body["manifest"] == "playground-example"
    assert body["findings"] == [f.to_dict() for f in direct.findings]
    assert body["finding_count"] == len(direct.findings)
    assert body["finding_count"] > 0
    assert body["summary"]["critical"] >= 1
    assert body["highest_severity"] == "critical"
    assert sum(body["summary"].values()) == body["finding_count"]


def test_finding_shape_carries_remediation(client: TestClient) -> None:
    body = client.post("/audit", json=EXAMPLE_MANIFEST).json()
    for finding in body["findings"]:
        assert finding["severity"]
        assert finding["title"]
        assert finding["explanation"]
        assert finding["remediation"]
        assert finding["severity_rationale"]


def test_audit_clean_manifest_has_no_findings(client: TestClient) -> None:
    resp = client.post("/audit", json=CLEAN_MANIFEST)
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_count"] == 0
    assert body["highest_severity"] is None


def test_audit_empty_surface_lists_are_fine(client: TestClient) -> None:
    manifest = {"server": {"name": "tiny"}, "tools": [], "resources": [], "prompts": []}
    resp = client.post("/audit", json=manifest)
    assert resp.status_code == 200
    assert resp.json()["finding_count"] == 0


def test_invalid_json_is_a_clean_400(client: TestClient) -> None:
    resp = client.post(
        "/audit",
        content="{not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_json"


def test_non_object_body_is_a_clean_400(client: TestClient) -> None:
    resp = client.post("/audit", json=["just", "a", "list"])
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "manifest_must_be_object"


def test_no_auditable_surface_is_a_422(client: TestClient) -> None:
    resp = client.post("/audit", json={"server": {"name": "empty"}})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "no_auditable_surface"


def test_oversized_manifest_is_a_413() -> None:
    small = TestClient(create_app(max_manifest_bytes=64))
    resp = small.post("/audit", content=json.dumps(EXAMPLE_MANIFEST))
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "manifest_too_large"


def test_index_lists_the_ui(client: TestClient) -> None:
    body = client.get("/").json()
    assert "ui" in body["endpoints"]


def test_ui_serves_the_single_page_frontend(client: TestClient) -> None:
    resp = client.get("/ui")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    page = resp.text
    # The paste box, the audit action, and the share-link machinery.
    assert 'id="manifest"' in page
    assert 'id="audit"' in page
    assert 'id="share"' in page
    assert "encodeManifest" in page
    assert "#m=" in page
    # Severity coloring for every level the API can return.
    for severity in ("critical", "high", "medium", "low"):
        assert f".pill.{severity}" in page
        assert f".badge.{severity}" in page
    # Findings are rendered with textContent, never as raw HTML.
    assert "textContent" in page


def test_ui_page_is_self_contained(client: TestClient) -> None:
    page = client.get("/ui").text
    # No build step and no framework means no external assets at all:
    # no script or stylesheet is loaded from anywhere else.
    assert "<script src=" not in page
    assert "<link" not in page
    assert 'src="http' not in page
    assert 'href="http' not in page.replace('href="https://github.com/anushamukka9/mcp-audit"', "")
