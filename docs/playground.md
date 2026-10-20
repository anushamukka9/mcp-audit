# The playground

The playground is the demo site for mcp-audit: paste a manifest in
the browser, get the audit report back, severity colors and all.
It has two halves, both in `playground/`: a small FastAPI backend
(`app.py`) that wraps the library, and one static frontend page
(`static/index.html`, no build step, no framework) that the backend
serves at `/ui`.

## Why a service at all

The CLI is the tool I use, but nobody stars a CLI they cannot try.
A paste-and-see page is the fastest honest demo of what the 28
checks do: the vulnerable example comes back with 11 findings and
plain-English remediation, and a clean manifest comes back empty.
The service exists to make that first look take ten seconds.

## How the backend is built

One rule shaped the code: the service calls `audit_server()` from
the library, the exact function the CLI runs. There is no second
implementation of the audit to keep in sync, and a test
(`test_audit_example_matches_the_library`) asserts the API response
is byte-for-byte the library's report for the same manifest.

- `playground/app.py` is the whole service: five routes, input
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

## How the frontend is built

One static page, on purpose. `playground/static/index.html` is a
single file with inline CSS and JS: no build step to break, no
framework to update, nothing loaded from anywhere else. Open it,
view source, and you have read the whole frontend.

- It posts the pasted manifest to `POST /audit` on its own origin
  (opened as a bare file, it falls back to
  `http://127.0.0.1:8000`; `?api=` points it at a deployed
  backend).
- Findings render severity-colored, with the target, the check,
  the explanation, the severity rationale, and the remediation.
  Every finding field is set with `textContent`, never as HTML.
  A manifest is untrusted input, and a breached one does not get
  to write the report page.
- Share links carry the manifest, not an id. **Copy share link**
  encodes the manifest as base64url in the URL fragment (`#m=`).
  Browsers never send fragments to a server, so the manifest goes
  to the person you send the link to and nowhere else. Opening a
  share link preloads the manifest and runs the audit on load.
  The honest cost: big manifests make big links, and some chat
  apps truncate them. The page says so, and pasting the JSON
  always works.
- Two examples are one click away: the vulnerable one is fetched
  from the backend (`GET /example`, 11 findings), the clean one
  is built into the page (0 findings). That contrast is the demo.

## Running and deploying

Local: `pip install -e .`, `pip install -r
playground/requirements.txt`, `python -m playground.app`, then
open `http://127.0.0.1:8000/ui`. `HOST` and `PORT` come from the
environment because hosting platforms assign the port.

The deployment target (Fly.io or Hugging Face Spaces) is still my
call to make; the service is written to drop into either unchanged,
and the frontend needs no separate hosting because the backend
serves it. What is not done yet, and is stated here so nobody
mistakes this for production hardening: no authentication, no
per-IP rate limiting, no request logging policy beyond the
platform default. Those land with, or before, a public deployment,
not after.

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
