# mcp-audit playground

The public playground: paste an MCP server manifest in your browser,
get the full audit report back with severity colors and a plain
fix for every finding. Two halves, both in this directory:

- `app.py` is the backend, a small FastAPI service that wraps the
  library. It serves the API and the page.
- `static/index.html` is the frontend, one static page. No build
  step, no framework, no external assets: inline CSS and JS.

## Run it

From the repo root:

```bash
pip install -e .
pip install -r playground/requirements.txt
python -m playground.app
```

Then open http://127.0.0.1:8000/ui in a browser. Paste a manifest,
hit **Audit manifest**. Or drive the API directly:

```bash
curl localhost:8000/healthz
curl localhost:8000/example > manifest.json
curl -X POST localhost:8000/audit --data @manifest.json
```

The example manifest is deliberately vulnerable: the audit comes
back with 11 findings, 2 of them critical. The clean example on the
page comes back with zero.

## What the page does

- Paste JSON, or load the vulnerable example (fetched from
  `GET /example`) or the clean example (built into the page).
- Findings render severity-colored (critical, high, medium, low)
  with the target, the check, the explanation, why that severity,
  and the remediation. Every finding field is rendered as text,
  never as HTML, so a hostile manifest cannot write the page.
- **Copy share link** encodes the manifest into the link itself
  (base64url in the URL fragment, the `#m=` part). Fragments never
  reach a server, so the link shares the manifest with whoever you
  send it to and nobody else. Opening a share link preloads the
  manifest and runs the audit right away.
- The page talks to the API on its own origin. Opened as a bare
  file it falls back to `http://127.0.0.1:8000`, and `?api=` points
  it at a deployed backend, for example
  `index.html?api=https://your-deployment.example`.

## Endpoints

| Route | What it does |
|---|---|
| `GET /` | Service info: version, check count, endpoint list |
| `GET /healthz` | `{"status": "ok"}` for platform health checks |
| `GET /example` | A small vulnerable manifest to try the audit with |
| `GET /ui` | The single-page frontend |
| `POST /audit` | Audit the manifest in the request body |

`POST /audit` returns the library's report (`manifest`, `summary`,
`findings` with severity, rationale, explanation, and remediation)
plus `finding_count`, `highest_severity`, and `checks_run`.

Errors are JSON with a stable shape,
`{"error": {"code": ..., "message": ...}}`: 400 for a body that is
not JSON or not an object, 413 past the 256 KB manifest cap, 422
for a manifest with no tools, resources, or prompts lists to audit.
The page shows those messages as sentences, not stack traces.

## Tests

```bash
pip install pytest httpx
python -m pytest playground/tests -q
```

14 tests: the API happy paths, the clean manifest, every error
shape, a parity test against the library, and the frontend tests
(the page is served, carries the paste box and share link logic,
is severity-colored for every level, and loads no external assets).

## Honest limits

- Stateless by design. Manifests are audited in memory and
  forgotten. Nothing is stored or logged, which also means there is
  no history and no accounts. Share links carry the manifest in the
  URL instead of on a server, on purpose.
- Share links get long. A big manifest makes a big URL, and some
  chat apps truncate long links. For a large manifest, send the
  JSON file and let the other person paste it.
- No authentication and no per-IP rate limiting yet. Fine for a
  demo on a platform with its own edge controls; add both before
  exposing this on the open internet under your own domain.
- The bind defaults to 127.0.0.1. `HOST` and `PORT` come from the
  environment; set `HOST=0.0.0.0` only inside a container or Space
  that is meant to be reached.

Full notes: [docs/playground.md](../docs/playground.md).
