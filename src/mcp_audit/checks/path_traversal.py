"""Flags file-reading tools that take unguarded paths.

Path traversal is the flaw I see most often in MCP servers I review: a
read_file tool that joins a caller-supplied path onto a base directory
without checking for ".." hands the whole filesystem to anyone who can
steer the model. This check flags tools that read files at caller-supplied
paths while their description mentions no traversal guard: no sandboxing,
jailing, canonicalization, allowlist, or stated directory confinement.

It reads the manifest, not the server. A tool can validate paths
server-side without saying so, and this check will flag it anyway. Treat a
hit as "confirm the guard exists", not as an exploitable hole. Writes are
broad_tool's territory; this check covers reads, opens, and downloads.

Complements weak_input_schema: a path parameter can carry schema
validation (like maxLength) and still be fully traversable.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_READ_VERB = re.compile(r"\b(read|open|load|view|cat|fetch|download)\b", re.I)
_PATH_PARAM = re.compile(r"\b(path|file|filename|filepath|dir|directory|folder)\b", re.I)
_GUARD = re.compile(
    r"\b(traversal|sandbox(?:ed)?|jail(?:ed)?|chroot|canonicali[sz]e[sd]?|"
    r"allowlist(?:ed)?|whitelist(?:ed)?|confined|restrict(?:ed|ion|s)?|"
    r"rejects? (?:\.\.|dot-dot))\b"
    r"|\b(?:from|in|under|within) (?:the |a )?[\w\-/ ]*(?:directory|folder|root)\b",
    re.I,
)


class PathTraversalCheck(Check):
    id = "path_traversal"
    title = "File-reading tool with unguarded paths"
    description = (
        "Tools that read files at caller-supplied paths with no described "
        "traversal guard invite directory traversal."
    )
    default_severity = "high"

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            description = tool.get("description", "")
            if not _READ_VERB.search(f"{name} {description}"):
                continue
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            path_params = sorted(
                param
                for param, spec in props.items()
                if isinstance(spec, dict)
                and spec.get("type") == "string"
                and _PATH_PARAM.search(param)
            )
            if not path_params:
                continue
            if _GUARD.search(description):
                continue
            params = ", ".join(f"'{param}'" for param in path_params)
            findings.append(
                self.finding(
                    target=f"tool:{name}",
                    title=f"Tool '{name}' reads files at unguarded paths",
                    explanation=(
                        f"The tool reads files, and {params} look like "
                        f"caller-supplied paths, but the description mentions no "
                        f"traversal guard. If the server joins the path without "
                        f"checking for '..', a steered model can read files "
                        f"outside the intended directory."
                    ),
                    remediation=(
                        "Canonicalize the path server-side, reject '..' and "
                        "absolute paths, and confine reads to one directory. "
                        "Say so in the tool description so auditors can see "
                        "the guard without reading your code."
                    ),
                    severity="high",
                )
            )
        return findings
