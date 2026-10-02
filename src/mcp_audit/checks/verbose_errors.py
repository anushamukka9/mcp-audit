"""Flags hints that the server discloses verbose error internals.

Stack traces and debug blobs are useful to developers and to attackers in
exactly the same way: they reveal file paths, library versions, and code
structure. This check looks for mentions of stack traces or debug output in
tool descriptions and for error-shaped fields in output schemas. It reads
documentation, not behavior, so it can only flag the intent to be verbose,
not the verbosity itself.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_VERBOSE = re.compile(
    r"\b(stack ?trace|traceback|debug (info|output|mode)|internal error details)\b", re.I
)
_ERROR_FIELD = re.compile(r"\b(stacktrace|stack_trace|traceback|debug_info)\b", re.I)


class VerboseErrorsCheck(Check):
    id = "verbose_errors"
    title = "Verbose error disclosure"
    description = (
        "Descriptions or schemas advertising stack traces and debug output "
        "suggest the server leaks internals on failure."
    )
    default_severity = "low"
    severity_rationale = (
        "Low because this is an information leak, not a control failure. Stack traces reveal "
        "paths and versions, which help an attacker enumerate but do not hand them access. Fix it "
        "the next time you are in the file."
    )

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            description = tool.get("description", "") or ""
            schema_text = str(tool.get("outputSchema", "") or "")
            if _VERBOSE.search(description):
                findings.append(
                    self.finding(
                        target=f"tool:{name}",
                        title=f"Tool '{name}' advertises verbose errors",
                        explanation=(
                            "The description mentions stack traces or debug "
                            "output. If errors really include that detail, every "
                            "failure hands an attacker file paths, versions, and "
                            "code structure."
                        ),
                        remediation=(
                            "Return short, stable error messages to callers and "
                            "keep the detailed traces in server-side logs."
                        ),
                    )
                )
            elif _ERROR_FIELD.search(schema_text):
                findings.append(
                    self.finding(
                        target=f"tool:{name}",
                        title=f"Tool '{name}' output schema exposes error internals",
                        explanation=(
                            "The output schema contains error-internals fields "
                            "(stack trace, traceback, debug info). Structured "
                            "error detail is convenient and also a clean feed of "
                            "internals to anyone who can trigger a failure."
                        ),
                        remediation=(
                            "Drop internals fields from the output schema. Log "
                            "them server-side with a correlation id instead."
                        ),
                    )
                )
        return findings
