"""Known-vulnerable package feed: the threat-intel layer for mcp-audit.

The static checks read a manifest and reason about its shape. This module
answers a different question: is this server, or one of the packages it
runs, a thing that already has a CVE? The feed is a plain JSON file:

    {
        "feed_version": 1,
        "updated": "2026-10-17",
        "entries": [
            {
                "id": "CVE-2026-59726",
                "package": "ruflo",
                "aliases": [],
                "affected": "*",
                "severity": "critical",
                "summary": "Unauthenticated RCE in the MCP bridge.",
                "references": ["https://..."]
            }
        ]
    }

``affected`` is a small version-range language: ``*`` matches every
version, and comma-separated clauses like ``<2.0.0``, ``<=1.4.2``,
``>=1.0.0,<1.2.0``, or ``==1.3.1`` must all hold. Versions are dotted
numbers (``1``, ``1.2``, ``1.2.3``); a suffix after ``-`` or ``+`` is
ignored for comparison, which is a simplification and is documented as
one in docs/cve-feed.md.

Design rules, same as the rest of the tool:

- Offline by default. The bundled snapshot ships inside the package and
  the scan never touches the network to check it. Refreshing the feed
  is your job: pass ``--cve-feed your-feed.json`` or call
  ``load_feed(path)``. A stale feed is a known limitation, stated
  plainly, not a surprise.
- Names match exactly after normalization (lowercase, ``-``/``_``/``.``
  folded together, npm scope kept). ``ruflo-fork`` does not match
  ``ruflo``. Substring matching would cry wolf on every fork.
- Package candidates come from places a manifest or a client config
  already names a package: the server block (``name``, ``package``,
  ``version``), a ``dependencies`` list, and client-config stdio
  entries (the package spec in the runner args, where the version can
  ride along as ``name@1.2.3``).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .core import SEVERITIES

BUNDLED_FEED_PATH = Path(__file__).resolve().parent / "data" / "cve_feed.json"

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)")
_PACKAGE_SPEC_RE = re.compile(
    r"^(?P<name>@[a-z0-9][a-z0-9-._~]*/[a-z0-9][a-z0-9-._~]*|[a-z0-9][a-z0-9-._~]*)"
    r"(?:@(?P<version>[^@\s]+))?$"
)
_LOCAL_PREFIXES = ("file:", "./", "../", "/", "~", "git+", "http://", "https://")
_RUNNERS = {"npx", "uvx", "bunx", "dlx"}


def normalize_package_name(name: str) -> str:
    """Fold case and separators so npm and PyPI spellings meet in the middle."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """Parse a dotted numeric version. Returns None when there is none."""
    if not text:
        return None
    match = _VERSION_RE.match(str(text).strip().lstrip("vV"))
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _padded(version: tuple[int, ...], width: int) -> tuple[int, ...]:
    return version + (0,) * (width - len(version))


def version_satisfies(version: str, spec: str) -> bool | None:
    """True/False when the version parses, None when it does not.

    A None here means "cannot confirm", which the check treats
    differently from a confirmed match.
    """
    parsed = parse_version(version)
    if parsed is None:
        return None
    spec = (spec or "*").strip()
    if spec in ("", "*"):
        return True
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause or clause == "*":
            continue
        op = "=="
        raw = clause
        for prefix in ("<=", ">=", "==", "!=", "<", ">", "="):
            if clause.startswith(prefix):
                op = "==" if prefix == "=" else prefix
                raw = clause[len(prefix) :].strip()
                break
        target = parse_version(raw)
        if target is None:
            return None
        width = max(len(parsed), len(target))
        left, right = _padded(parsed, width), _padded(target, width)
        holds = {
            "<": left < right,
            "<=": left <= right,
            ">": left > right,
            ">=": left >= right,
            "==": left == right,
            "!=": left != right,
        }[op]
        if not holds:
            return False
    return True


@dataclass
class CveEntry:
    """One known-vulnerable package record from a feed."""

    id: str
    package: str
    affected: str = "*"
    severity: str = "high"
    summary: str = ""
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def names(self) -> set[str]:
        return {normalize_package_name(self.package)} | {
            normalize_package_name(alias) for alias in self.aliases
        }

    def affects(self, version: str | None) -> bool | None:
        """True confirmed, False fixed, None cannot confirm (no version)."""
        if version is None:
            return None
        return version_satisfies(version, self.affected)

    @classmethod
    def from_dict(cls, data: dict) -> CveEntry:
        severity = str(data.get("severity", "high")).lower()
        if severity not in SEVERITIES:
            raise ValueError(f"feed entry {data.get('id')!r}: bad severity {severity!r}")
        if not data.get("id") or not data.get("package"):
            raise ValueError("feed entries need at least 'id' and 'package'")
        return cls(
            id=str(data["id"]),
            package=str(data["package"]),
            affected=str(data.get("affected", "*")),
            severity=severity,
            summary=str(data.get("summary", "")),
            aliases=[str(a) for a in data.get("aliases", [])],
            references=[str(r) for r in data.get("references", [])],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "package": self.package,
            "aliases": list(self.aliases),
            "affected": self.affected,
            "severity": self.severity,
            "summary": self.summary,
            "references": list(self.references),
        }


@dataclass
class CveFeed:
    """A loaded feed: entries plus the snapshot metadata that dates it."""

    entries: list[CveEntry] = field(default_factory=list)
    updated: str = ""
    feed_version: int = 1

    def match(self, package: str) -> list[CveEntry]:
        """Entries whose package name or aliases match, exactly."""
        wanted = normalize_package_name(package)
        return [entry for entry in self.entries if wanted in entry.names()]

    @classmethod
    def from_dict(cls, data: dict) -> CveFeed:
        if not isinstance(data, dict):
            raise ValueError("feed must be a JSON object")
        return cls(
            entries=[CveEntry.from_dict(e) for e in data.get("entries", [])],
            updated=str(data.get("updated", "")),
            feed_version=int(data.get("feed_version", 1)),
        )


def load_feed(path: str | Path | None = None) -> CveFeed:
    """Load a feed file, or the bundled snapshot when no path is given."""
    feed_path = Path(path) if path is not None else BUNDLED_FEED_PATH
    with open(feed_path, encoding="utf-8") as fh:
        return CveFeed.from_dict(json.load(fh))


@dataclass
class PackageCandidate:
    """A package named somewhere in a manifest, with what we know of it."""

    package: str
    version: str | None
    target: str
    origin: str


def split_package_spec(spec: str) -> tuple[str, str | None] | None:
    """Split 'name@1.2.3' or '@scope/name@1.2.3' into (name, version).

    Returns None for local paths, URLs, and args that are not package
    specs at all (scripts, flags, plain words with no registry shape are
    still returned as names; the feed decides whether they matter).
    """
    spec = spec.strip()
    if not spec or spec.startswith("-") or spec.startswith(_LOCAL_PREFIXES):
        return None
    match = _PACKAGE_SPEC_RE.match(spec)
    if not match:
        return None
    version = match.group("version")
    if version and (version == "latest" or not _VERSION_RE.match(version.lstrip("vV"))):
        version = None  # a tag like @latest is a name check, not a version
    return match.group("name"), version


def _server_candidates(manifest: dict) -> list[PackageCandidate]:
    server = manifest.get("server", {}) or {}
    name = str(server.get("name", "") or "")
    target = f"server:{name or 'unknown'}"
    candidates: list[PackageCandidate] = []
    package = server.get("package")
    if package:
        split = split_package_spec(str(package))
        if split:
            pkg_name, spec_version = split
            candidates.append(
                PackageCandidate(
                    package=pkg_name,
                    version=str(server.get("version") or spec_version or "") or None,
                    target=target,
                    origin="server.package",
                )
            )
    if name and not candidates:
        split = split_package_spec(name)
        if split:
            pkg_name, spec_version = split
            candidates.append(
                PackageCandidate(
                    package=pkg_name,
                    version=str(server.get("version") or spec_version or "") or None,
                    target=target,
                    origin="server.name",
                )
            )
    return candidates


def _dependency_candidates(manifest: dict) -> list[PackageCandidate]:
    candidates: list[PackageCandidate] = []
    for dep in manifest.get("dependencies", []) or []:
        if isinstance(dep, str):
            split = split_package_spec(dep)
            if split:
                pkg_name, spec_version = split
                candidates.append(
                    PackageCandidate(pkg_name, spec_version, f"package:{pkg_name}", "dependencies")
                )
        elif isinstance(dep, dict):
            raw = str(dep.get("name") or dep.get("package") or "")
            if not raw:
                continue
            split = split_package_spec(raw)
            if split:
                pkg_name, spec_version = split
                version = str(dep.get("version") or spec_version or "") or None
                candidates.append(
                    PackageCandidate(pkg_name, version, f"package:{pkg_name}", "dependencies")
                )
    return candidates


def _client_candidates(manifest: dict) -> list[PackageCandidate]:
    candidates: list[PackageCandidate] = []
    for server in manifest.get("client_servers", []) or []:
        name = str(server.get("name", "?") or "?")
        target = f"server:{name}"
        if server.get("transport") == "stdio":
            command = str(server.get("command", "") or "")
            base = command.rsplit("/", 1)[-1].lower()
            args = [str(a) for a in (server.get("args") or [])]
            if base == "pnpm" and args[:1] == ["dlx"]:
                args = args[1:]
                base = "dlx"
            if base in _RUNNERS:
                for arg in args:
                    split = split_package_spec(arg)
                    if split:
                        pkg_name, spec_version = split
                        candidates.append(
                            PackageCandidate(
                                pkg_name, spec_version, target, "client config package"
                            )
                        )
                        break
                continue
        raw_name = str(server.get("package") or name)
        split = split_package_spec(raw_name)
        if split:
            pkg_name, spec_version = split
            version = str(server.get("version") or spec_version or "") or None
            candidates.append(PackageCandidate(pkg_name, version, target, "client config entry"))
    return candidates


def extract_package_candidates(manifest: dict) -> list[PackageCandidate]:
    """Every package a manifest names, deduplicated by (package, target)."""
    seen: set[tuple[str, str]] = set()
    candidates: list[PackageCandidate] = []
    for candidate in (
        _server_candidates(manifest)
        + _dependency_candidates(manifest)
        + _client_candidates(manifest)
    ):
        key = (normalize_package_name(candidate.package), candidate.target)
        if key not in seen:
            seen.add(key)
            candidates.append(candidate)
    return candidates


__all__ = [
    "BUNDLED_FEED_PATH",
    "CveEntry",
    "CveFeed",
    "PackageCandidate",
    "extract_package_candidates",
    "load_feed",
    "normalize_package_name",
    "parse_version",
    "split_package_spec",
    "version_satisfies",
]
