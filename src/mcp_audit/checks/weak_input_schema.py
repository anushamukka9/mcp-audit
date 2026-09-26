"""Flags security-sensitive parameters with no input validation.

A "path" parameter typed as a bare string with no pattern, enum, or length
bound is an invitation to path traversal; a "command" parameter with no
constraints is an invitation to worse. This check looks at string-typed
parameters whose names suggest they carry paths, URLs, commands, or queries,
and flags the ones with no validation keywords at all. It only inspects the
schema: it cannot see server-side validation, so a flagged parameter may be
perfectly safe behind the scenes. Treat hits as "confirm the validation
exists", not as vulnerabilities.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_SENSITIVE_PARAM = re.compile(
    r"\b(path|file|filename|filepath|dir|directory|url|uri|endpoint|"
    r"command|cmd|script|query|sql|shell|args?|payload|content|body)\b",
    re.I,
)
_VALIDATION_KEYS = ("enum", "pattern", "minLength", "maxLength", "const", "format")


class WeakInputSchemaCheck(Check):
    id = "weak_input_schema"
    title = "Sensitive parameter without input validation"
    description = (
        "Free-form string parameters for paths, URLs, or commands with no "
        "schema-level validation invite traversal and injection."
    )
    default_severity = "medium"

    def _properties(self, schema: dict) -> dict:
        if not isinstance(schema, dict):
            return {}
        props = schema.get("properties", {})
        return props if isinstance(props, dict) else {}

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            for param_name, param in self._properties(tool.get("inputSchema", {})).items():
                if not isinstance(param, dict):
                    continue
                if param.get("type") != "string":
                    continue
                if not _SENSITIVE_PARAM.search(param_name):
                    continue
                if any(key in param for key in _VALIDATION_KEYS):
                    continue
                findings.append(
                    self.finding(
                        target=f"tool:{name}",
                        title=f"Parameter '{param_name}' on tool '{name}' has no validation",
                        explanation=(
                            f"The '{param_name}' parameter accepts any string with "
                            f"no enum, pattern, or length bound in the schema. "
                            f"Names like this usually carry paths, URLs, or "
                            f"commands, where unconstrained input means "
                            f"traversal or injection risk."
                        ),
                        remediation=(
                            f"Constrain '{param_name}' in the schema: a pattern "
                            f"for paths, an enum or format for URLs, a maxLength "
                            f"everywhere. Then enforce the same rules server-side, "
                            f"because clients can ignore the schema."
                        ),
                    )
                )
        return findings
