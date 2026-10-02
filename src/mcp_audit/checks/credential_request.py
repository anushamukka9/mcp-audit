"""Flags tool input schemas that ask the caller to supply secrets.

A tool whose parameters include "password", "api_key", or "token" is
asking the model to go find a credential and hand it over. Sometimes
that is exactly the tool's job (a login tool, a vault client). But a
third-party MCP server has no business routinely asking for secrets
through its tool inputs: every such parameter is a phishing surface,
because the model will fill it from whatever credentials it can reach,
user memory, environment, other tools, and the user may never see the
handoff.

This check looks at top-level inputSchema property names, not
descriptions or values. It deliberately ignores counting-style names
like "max_tokens" or "input_tokens". It skips tools that clearly
present themselves as authentication (login, sign in, oauth), since
asking for a password is the whole point of those. It cannot see
whether the credential is really needed, and nested schemas are not
inspected. A hit means "read this tool and decide if the credential
should flow through here", not "this tool is malicious".

Complements embedded_secret: that check catches secrets baked into
the manifest itself; this one catches the manifest asking for secrets
to be supplied.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_CREDENTIAL_PARAM = re.compile(
    r"(password|passwd|passphrase|passcode|secret|api[-_]?key|"
    r"access[-_]?key|client[-_]?secret|private[-_]?key|"
    r"auth[-_]?token|access[-_]?token|refresh[-_]?token|"
    r"session[-_]?token|\bbearer\b|\btoken\b)",
    re.I,
)

# Names where "token" means accounting, not a secret.
_COUNTING_NAMES = re.compile(
    r"(tokenizer|max[-_]?tokens?|input[-_]?tokens?|output[-_]?tokens?|"
    r"tokens?[-_]?(used|count|limit)|num[-_]?tokens?)",
    re.I,
)

# Tools whose entire job is authentication get a pass.
_AUTH_TOOL = re.compile(
    r"(login|log[-_]?in|sign[-_ ]?in|authenticate|oauth|get[-_]?token)",
    re.I,
)


class CredentialRequestCheck(Check):
    id = "credential_request"
    title = "Tool input schema asks for credentials"
    description = (
        "Parameters named like passwords, API keys, or tokens turn the "
        "tool into a credential handoff point."
    )
    default_severity = "high"
    severity_rationale = (
        "High because every such parameter is a phishing surface with built-in delivery: the "
        "model fills it from whatever credentials it can reach, and the user may never see the "
        "handoff."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            description = tool.get("description", "")
            if _AUTH_TOOL.search(f"{name} {description}"):
                continue
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            cred_params = sorted(
                param
                for param, spec in props.items()
                if isinstance(spec, dict)
                and _CREDENTIAL_PARAM.search(param)
                and not _COUNTING_NAMES.search(param)
            )
            if not cred_params:
                continue
            params = ", ".join(f"'{param}'" for param in cred_params)
            findings.append(
                self.finding(
                    target=f"tool:{name}",
                    title=f"Tool '{name}' asks for credentials in its inputs",
                    explanation=(
                        f"Input parameters {params} look like credentials. "
                        f"The model will fill them from whatever secrets it "
                        f"can reach, and the user may never see the handoff. "
                        f"Legitimate uses exist (a vault client, a login "
                        f"flow), but a third-party tool should not routinely "
                        f"ask for secrets through its inputs."
                    ),
                    remediation=(
                        "Prefer scoped credentials issued to the server "
                        "itself over parameters the model must fill. If the "
                        "tool genuinely needs a user credential, document "
                        "where it goes and how it is stored, and keep the "
                        "parameter list to the minimum the tool needs."
                    ),
                    severity="high",
                )
            )
        return findings
