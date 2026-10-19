"""Flags servers and packages that match a known-vulnerable feed entry.

This is the one check that is not pattern matching over manifest shape.
It compares the package names a manifest declares (the server block, a
dependencies list, and client-config stdio entries) against a feed of
disclosed vulnerabilities and reports the matches with their CVE ids.

Three outcomes per match, and the finding says which one it is:

- Version declared and inside the affected range: a confirmed match.
  The finding carries the entry severity from the advisory.
- Version declared and outside the range: silence. You patched; the
  check does not congratulate you, it just moves on.
- No version declared: an unconfirmed match at medium. The name matches
  a vulnerable package and nothing in the manifest proves you are on a
  fixed release, so the finding asks you to check, in those words.

The feed is offline. The bundled snapshot is small and dated (see
``mcp_audit.cve_feed`` and docs/cve-feed.md); swap in your own with
``--cve-feed`` or by constructing the check with a loaded ``CveFeed``.
Name matching is exact after normalization. Forks and similarly named
packages do not match, on purpose.

Limitations: the check can only see packages the manifest names. A
server that declares no package, no dependencies, and a marketing name
is invisible to it. The bundled snapshot is two entries I could source
to a specific disclosure, not a database; treat a clean result here as
"no match in this feed", never as "no known vulnerabilities".
"""

from __future__ import annotations

from ..core import Finding
from ..cve_feed import CveFeed, extract_package_candidates, load_feed
from .base import Check


class KnownVulnerablePackageCheck(Check):
    id = "known_vulnerable_package"
    title = "Package matches a known-vulnerable feed entry"
    description = (
        "The server, one of its declared dependencies, or a client-config "
        "package matches a disclosed-vulnerability feed entry (CVE id "
        "included in the finding)."
    )
    default_severity = "high"
    severity_rationale = (
        "A confirmed match is not a pattern guess: the package and version "
        "sit inside a disclosed vulnerability's affected range, so the "
        "finding carries the advisory's own severity. When the version is "
        "not declared the match cannot be confirmed, so the finding drops "
        "to medium and says so."
    )

    def __init__(self, feed: CveFeed | None = None) -> None:
        self.feed = feed if feed is not None else load_feed()

    def run(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        for candidate in extract_package_candidates(manifest):
            for entry in self.feed.match(candidate.package):
                verdict = entry.affects(candidate.version)
                if verdict is False:
                    continue
                refs = f" References: {', '.join(entry.references)}." if entry.references else ""
                if verdict is True:
                    findings.append(
                        self.finding(
                            target=candidate.target,
                            title=(
                                f"{entry.id}: package '{candidate.package}' "
                                f"{candidate.version} is in the affected range "
                                f"({entry.affected})"
                            ),
                            explanation=(
                                f"The {candidate.origin} names package "
                                f"'{candidate.package}' at version "
                                f"{candidate.version}, which the feed snapshot "
                                f"dated {self.feed.updated or 'unknown'} lists "
                                f"under {entry.id} (affected: {entry.affected}). "
                                f"{entry.summary}{refs}"
                            ),
                            remediation=(
                                "Move to a version outside the affected range, "
                                "or remove the package, and confirm against the "
                                "advisory itself before you call it fixed. If "
                                "the package is not actually this one, rename "
                                "the declaration so the next scan is unambiguous."
                            ),
                            severity=entry.severity,
                        )
                    )
                else:
                    findings.append(
                        self.finding(
                            target=candidate.target,
                            title=(
                                f"{entry.id}: package '{candidate.package}' matches "
                                "a vulnerable name, version not declared"
                            ),
                            explanation=(
                                f"The {candidate.origin} names package "
                                f"'{candidate.package}', which the feed snapshot "
                                f"dated {self.feed.updated or 'unknown'} lists "
                                f"under {entry.id} (affected: {entry.affected}), "
                                f"but no version is declared, so I cannot confirm "
                                f"you are affected or clear you. {entry.summary}"
                                f"{refs}"
                            ),
                            remediation=(
                                "Declare the exact version you run, then check "
                                "it against the advisory. If it sits inside the "
                                "affected range, upgrade or remove the package. "
                                "Pinning the version also makes the next scan "
                                "give you a straight answer."
                            ),
                            severity="medium",
                        )
                    )
        return findings
