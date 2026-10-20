# The playground backend

The playground is the demo site for mcp-audit: paste a manifest in
the browser, get the audit report back, severity colors and all.
This page covers the backend, a small FastAPI service in
`playground/` that wraps the library. The frontend is a separate
slice (one static page, no build step).

## Why a service at all

The CLI is the tool I use, but nobody stars a CLI they cannot try.
A paste-and-see page is the fastest honest demo of what the 28
checks do: the vulnerable example comes back with 11 findings and
plain-English remediation, and a clean manifest comes back empty.
The service exists to make that first look take ten seconds.

## How it is built

One rule shaped the code: the service calls `audit_server()` from
the library, the exact function the CLI runs. There is no second
implementation of the audit to keep in sync, and a test
(`test_audit_example_matches_the_library`) asserts the API response
is byte-for-byte the library's report for the same manifest.

- `playground/app.py` is the whole service: four routes, input
  guards, and a `create_app()` factory so tests can shrink the
  byte cap instead of posting padding.
- Input is refused before it is audited: non-JSON bodies and
  non-object bodies get a 400, bodies past 256 KB get a 413, and a
  manifest with no tools, resources, or prompts lists gets a 422
  explaining what a manifest needs. Every error is
  `{"error": {"code", "message"}}` so the frontend renders a
  sentence, not a stack trace.
- Stateless, deliberately. A manifest is audited in memory and
  forgotten; nothing is written to disk or a database. That keeps
  the privacy story one sentence long: I never see or keep what
  you paste.

## Running and deploying

Local: `pip install -e .`, `pip install -r
playground/requirements.txt`, `python -m playground.app`, on
127.0.0.1:8000. `HOST` and `PORT` come from the environment because
hosting platforms assign the port.

The deployment target (Fly.io or Hugging Face Spaces) is still my
call to make; the service is written to drop into either unchanged.
What is not done yet, and is stated here so nobody mistakes this
for production hardening: no authentication, no per-IP rate
limiting, no request logging policy beyond the platform default.
Those land with, or before, a public deployment, not after.

## What the audit response looks like

```json
{
  "manifest": "playground-example",
  "summary": {"critical": 2, "high": 3, "medium": 4, "low": 2},
  "finding_count": 11,
  "highest_severity": "critical",
  "checks_run": 28,
  "findings": [
    {
      "check_id": "broad_tool",
      "severity": "critical",
      "target": "tool:run_shell",
      "title": "...",
      "explanation": "...",
      "remediation": "...",
      "severity_rationale": "..."
    }
  ]
}
```

Every field the frontend needs for severity-colored findings with
remediation advice is already in the library's `Finding.to_dict()`;
the service adds only the three summary fields on top.
