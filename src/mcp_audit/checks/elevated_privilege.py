"""Flags tools and resources claiming elevated privileges or over-broad scope.

Least privilege is the rule MCP servers break most quietly. This check
looks at two shapes:

- privilege claims: descriptions saying a tool runs as root, uses sudo,
  bypasses permission checks, or gets unrestricted system access. Any of
  these turns a prompt-injection hit into a host compromise.
- scope claims: resources with wildcard templates (``file://{path}``) and
  tools advertised as reaching "any" file, URL, or host. The broader the
  scope, the less has to go wrong for something bad to happen.

This is phrase matching, so expect both misses and false alarms. A backup
tool that honestly requires admin access will flag; negated phrasing like
"does not require admin privileges" is filtered out, but paraphrases slip
through. Read the flagged item and decide whether the privilege is
necessary, documented, and actually enforced.
"""

from __future__ import annotations

import re

from ..core import Finding
from .base import Check

_PRIVILEGE_CLAIM = re.compile(
    r"\b(runs? as|with|using|requires?|needs?)\s+"
    r"(root|administrator|admin(istrator)?|superuser|elevated)\s+"
    r"(privileges?|access|permissions?|rights?)",
    re.I,
)
_SUDO = re.compile(r"\b(sudo|setuid|run as root|root shell)\b", re.I)
_BYPASS = re.compile(
    r"\b(bypass(es|ing)?|skips?|skipping|disables?|disabled)\s+"
    r"(permission|access|auth(orization)?|security)\s+(checks?|controls?|restrictions?)",
    re.I,
)
_FULL_ACCESS = re.compile(
    r"\b(full|complete|unrestricted|unlimited)\s+"
    r"(system|disk|filesystem|file system|network|admin(istrator|istrative)?)\s+"
    r"(access|control|permissions?)",
    re.I,
)
# "does not require admin privileges" must not flag.
_NEGATED = re.compile(r"\b(not|no|without|never|doesn.?t|won.?t)\b", re.I)
_ANYTHING = re.compile(r"\bany\s+(file|path|directory|folder|command)s?\b", re.I)
_WILDCARD_URI = re.compile(r"(\{[^}]*\}|\*)")


class ElevatedPrivilegeCheck(Check):
    id = "elevated_privilege"
    title = "Elevated privilege or over-broad scope claim"
    description = (
        "Tools claiming root/admin privileges or bypassing permission checks, "
        "and resources with wildcard scopes, widen every other finding's blast radius."
    )
    default_severity = "high"
    severity_rationale = (
        "High for privilege claims because privilege is a multiplier: a prompt "
        "injection that reaches a root-running tool is a host compromise, not a "
        "bad answer. Medium for broad scope claims, which are risky by default "
        "but often the tool's actual job."
    )

    def _privilege_hit(self, text: str) -> str | None:
        for pattern, why in [
            (_PRIVILEGE_CLAIM, "claims elevated privileges"),
            (_SUDO, "invokes sudo/root execution"),
            (_BYPASS, "bypasses permission or access checks"),
            (_FULL_ACCESS, "claims unrestricted system access"),
        ]:
            for match in pattern.finditer(text):
                before = text[max(0, match.start() - 40) : match.start()]
                if _NEGATED.search(before):
                    continue
                return why
        return None

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for tool in self.tools(manifest):
            name = tool.get("name", "?")
            text = f"{name} {tool.get('description', '')}"
            why = self._privilege_hit(text)
            if why:
                findings.append(
                    self.finding(
                        target=f"tool:{name}",
                        title=f"Tool '{name}' {why}",
                        explanation=(
                            f"The tool description {why}. Elevated privilege turns "
                            f"every other issue on this server into a bigger one: a "
                            f"prompt injection that reaches this tool inherits its "
                            f"privileges."
                        ),
                        remediation=(
                            "Drop the privilege if the tool does not need it. If it "
                            "does, document exactly what is elevated and enforce it "
                            "server-side; descriptions are claims, not controls."
                        ),
                    )
                )
                continue
            if _ANYTHING.search(text):
                findings.append(
                    self.finding(
                        target=f"tool:{name}",
                        title=f"Tool '{name}' advertises an unscoped reach",
                        explanation=(
                            "The description advertises reaching 'any' file, path, "
                            "or command. Unscoped reach means a confused or "
                            "steered model has the whole namespace to work with. "
                            "(Unscoped network fetch is covered by broad_tool.)"
                        ),
                        remediation=(
                            "Scope the tool to the paths or commands it "
                            "actually needs, and say so in the description."
                        ),
                        severity="medium",
                    )
                )
        for resource in self.resources(manifest):
            uri = resource.get("uri", "")
            name = resource.get("name", uri)
            if uri and uri.startswith("file://") and _WILDCARD_URI.search(uri):
                findings.append(
                    self.finding(
                        target=f"resource:{name}",
                        title=f"Resource '{name}' uses a wildcard file scope",
                        explanation=(
                            f"The resource URI ({uri}) contains a wildcard or "
                            f"template parameter over the filesystem. Combined with "
                            f"model readability, that is broad exposure behind one "
                            f"parameter."
                        ),
                        remediation=(
                            "Narrow the resource to the concrete paths the server means to expose."
                        ),
                        severity="medium",
                    )
                )
        return findings
