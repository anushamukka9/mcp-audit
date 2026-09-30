"""Report formatters: table, markdown, JSON, SARIF, and HTML.

Every formatter reads an AuditReport and nothing else, so library users
get the same output the CLI produces:

    from mcp_audit import audit_server
    from mcp_audit.report import format_report

    report = audit_server(manifest)
    html = format_report(report, "html")
"""

from __future__ import annotations

import html
import json

from . import __version__, default_checks
from .core import AuditReport

_FORMATS = ("table", "json", "sarif", "markdown", "html")


def format_table(report: AuditReport) -> str:
    lines = [f"mcp-audit: {report.manifest_name} - {len(report.findings)} finding(s)"]
    counts = report.counts()
    lines.append("severity: " + ", ".join(f"{sev}={counts[sev]}" for sev in counts))
    lines.append("")
    if not report.findings:
        lines.append("No findings. Nice manifest.")
        return "\n".join(lines)
    for finding in report.findings:
        lines.append(f"[{finding.severity.upper():8}] {finding.target}")
        lines.append(f"           {finding.title} ({finding.check_id})")
    return "\n".join(lines)


def format_markdown(report: AuditReport) -> str:
    lines = [f"# mcp-audit: {report.manifest_name}", ""]
    counts = report.counts()
    lines.append(" | ".join(f"{sev}: {counts[sev]}" for sev in counts))
    lines.append("")
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines)
    for finding in report.findings:
        lines.append(f"## [{finding.severity}] {finding.title}")
        lines.append(f"Target: `{finding.target}` - check: `{finding.check_id}`")
        lines.append("")
        lines.append(finding.explanation)
        lines.append("")
        if finding.severity_rationale:
            lines.append(f"*Why {finding.severity}:* {finding.severity_rationale}")
            lines.append("")
        lines.append(f"**Fix:** {finding.remediation}")
        lines.append("")
    return "\n".join(lines)


_SARIF_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _sarif_level(severity: str) -> str:
    return _SARIF_LEVELS[severity]


def format_sarif(report: AuditReport) -> str:
    """Minimal SARIF 2.1.0 output for CI code-scanning ingestion."""
    rules = [
        {
            "id": check.id,
            "name": check.title,
            "shortDescription": {"text": check.description},
        }
        for check in default_checks()
    ]
    results = [
        {
            "ruleId": f.check_id,
            "level": _sarif_level(f.severity),
            "message": {"text": f"{f.title}: {f.explanation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.target}}}],
        }
        for f in report.findings
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "mcp-audit", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


_SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#166534",
}


def format_html(report: AuditReport) -> str:
    """Standalone HTML report: one self-contained page, no external assets."""
    counts = report.counts()
    summary = " ".join(f'<span class="pill {sev}">{sev}: {counts[sev]}</span>' for sev in counts)
    if report.findings:
        cards = []
        for finding in report.findings:
            color = _SEVERITY_COLORS[finding.severity]
            rationale = ""
            if finding.severity_rationale:
                rationale = (
                    "<p class='rationale'><strong>Why "
                    + html.escape(finding.severity)
                    + ":</strong> "
                    + html.escape(finding.severity_rationale)
                    + "</p>"
                )
            cards.append(
                "<div class='card'>"
                f"<div class='badge' style='background:{color}'>"
                + html.escape(finding.severity.upper())
                + "</div>"
                "<div class='body'>"
                f"<h2>{html.escape(finding.title)}</h2>"
                f"<p class='meta'>Target <code>{html.escape(finding.target)}</code> "
                f"- check <code>{html.escape(finding.check_id)}</code></p>"
                f"<p>{html.escape(finding.explanation)}</p>"
                + rationale
                + f"<p><strong>Fix:</strong> {html.escape(finding.remediation)}</p>"
                + "</div></div>"
            )
        findings_html = "\n".join(cards)
    else:
        findings_html = "<p class='clean'>No findings. Nice manifest.</p>"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>mcp-audit: {html.escape(report.manifest_name)}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 860px; margin: 2rem auto;
       padding: 0 1rem; color: #1f2937; }}
.pill {{ display: inline-block; padding: 0.2rem 0.7rem; border-radius: 999px;
        color: #fff; margin-right: 0.4rem; font-size: 0.85rem; }}
.pill.critical {{ background: #b91c1c; }} .pill.high {{ background: #c2410c; }}
.pill.medium {{ background: #a16207; }} .pill.low {{ background: #166534; }}
.card {{ display: flex; gap: 1rem; border: 1px solid #e5e7eb; border-radius: 8px;
        padding: 1rem; margin: 1rem 0; }}
.badge {{ color: #fff; font-weight: 700; font-size: 0.75rem; height: fit-content;
         padding: 0.25rem 0.5rem; border-radius: 4px; white-space: nowrap; }}
.body h2 {{ margin: 0 0 0.3rem; font-size: 1.05rem; }}
.meta {{ color: #6b7280; font-size: 0.85rem; }}
.rationale {{ background: #f9fafb; border-left: 3px solid #d1d5db;
             padding: 0.5rem 0.8rem; font-size: 0.9rem; }}
.clean {{ color: #166534; font-weight: 600; }}
code {{ background: #f3f4f6; padding: 0.1rem 0.3rem; border-radius: 4px; }}
</style>
</head>
<body>
<h1>mcp-audit: {html.escape(report.manifest_name)}</h1>
<p>{summary}</p>
<p>{len(report.findings)} finding(s), generated by mcp-audit {html.escape(__version__)}</p>
{findings_html}
</body>
</html>
"""


def format_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


_FORMATTERS = {
    "table": format_table,
    "json": format_json,
    "sarif": format_sarif,
    "markdown": format_markdown,
    "html": format_html,
}


def format_report(report: AuditReport, format: str) -> str:
    """Render a report in one of: table, json, sarif, markdown, html."""
    try:
        return _FORMATTERS[format](report)
    except KeyError:
        raise ValueError(f"unknown format {format!r}; choose from {_FORMATS}") from None


__all__ = [
    "format_html",
    "format_json",
    "format_markdown",
    "format_report",
    "format_sarif",
    "format_table",
]
