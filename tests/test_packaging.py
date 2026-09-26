"""Packaging guards: version sync and entry points."""

import re
from pathlib import Path

import mcp_audit

ROOT = Path(__file__).resolve().parent.parent


def test_version_synced_with_pyproject():
    pyproject = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"', pyproject, re.M)
    assert match, "no version in pyproject.toml"
    assert match.group(1) == mcp_audit.__version__


def test_cli_entry_point_importable():
    from mcp_audit.cli import main

    assert callable(main)


def test_pyproject_declares_script():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "mcp-audit" in pyproject
    assert "mcp_audit.cli:main" in pyproject
