"""Flags secrets stored in plaintext in MCP client configs.

MCP client config files (Claude Desktop, Cursor, Claude Code) hold per
server ``env`` blocks, and people put real API keys in them because the
server needs them. The config file is plaintext JSON on disk, often
backed up, synced, or pasted into bug reports. This check flags env var
names that look like secrets (API_KEY, TOKEN, SECRET, PASSWORD,
PRIVATE_KEY) so the keys get moved somewhere safer.

One finding per server, listing the suspicious names. It cannot tell a
real key from a placeholder, so ``YOUR_API_KEY_HERE`` will fire too;
the remediation covers that.

These checks read ``manifest["client_servers"]``, which
``mcp_audit.client_config.scan_client_config`` builds from config
files. They stay silent on ordinary server manifests.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_SECRET_NAME = re.compile(
    r"(api[_-]?key|apikey|secret|token|password|passwd|private[_-]?key|client[_-]?secret)",
    re.I,
)
_PLACEHOLDER = re.compile(
    r"(your[_-]|example|placeholder|xxx+|changeme|test[_-]?key|dummy|fake)",
    re.I,
)


class ConfigPlaintextSecretCheck(Check):
    id = "config_plaintext_secret"
    title = "Possible secret in plaintext client config"
    description = (
        "An MCP server entry in a client config sets env vars whose names "
        "look like secrets. The config file is plaintext JSON on disk."
    )
    default_severity = "medium"
    severity_rationale = (
        "Medium because it is credential hygiene, not an active exploit: "
        "the key sits in a file that gets backed up, synced, and pasted "
        "into support threads. Real keys deserve a real secret store."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for server in manifest.get("client_servers", []) or []:
            env = server.get("env", {}) or {}
            suspicious = [k for k in env if _SECRET_NAME.search(str(k))]
            if not suspicious:
                continue
            name = server.get("name", "?")
            source = server.get("source", "config")
            looks_placeholder = all(_PLACEHOLDER.search(k) for k in suspicious)
            detail = ", ".join(sorted(suspicious))
            explanation = (
                f"The {source} config entry '{name}' sets {detail} in its "
                "env block. That file is plaintext JSON on disk, which means "
                "the value rides along with backups, dotfile repos, and "
                "screenshots of config problems."
            )
            if looks_placeholder:
                explanation += (
                    " The names look like placeholders, so this may be "
                    "harmless; the check flags the name, not the value."
                )
            findings.append(
                self.finding(
                    target=f"server:{name}",
                    title=f"'{name}' may store secrets in plaintext config",
                    explanation=explanation,
                    remediation=(
                        "Move real keys into the OS keychain or a secret "
                        "manager and reference them (e.g. launch the server "
                        "through a wrapper that injects the secret), and "
                        "keep the config file out of synced folders and "
                        "screenshots."
                    ),
                )
            )
        return findings
