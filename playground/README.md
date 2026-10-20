# mcp-audit playground (backend)

The API half of the public playground: paste an MCP server manifest,
get the full audit report in your browser. This directory is the
backend, a small FastAPI service that wraps the library. The
frontend is one static page and lands as its own slice; until then
the API stands on its own and is fully tested.

## Run it

From the repo root:

```bash
pip install -e .
pip install -r playground/requirements.txt
python -m playground.app
```

Then:

```bash
curl localhost:8000/healthz
curl localhost:8000/example > manifest.json
curl -X POST localhost:8000/audit --data @manifest.json
```

The example manifest is deliberately vulnerable: the audit comes
back with 11 findings, 2 of them critical. The repo's
`examples/clean_manifest.json` comes back with zero.

## Endpoints

| Route | What it does |
|---|---|
| `GET /` | Service info: version, check count, endpoint list |
| `GET /healthz` | `{"status": "ok"}` for platform health checks |
| `GET /example` | A small vulnerable manifest to try the audit with |
| `POST /audit` | Audit the manifest in the request body |

`POST /audit` returns the library's report (`manifest`, `summary`,
`findings` with severity, rationale, explanation, and remediation)
plus `finding_count`, `highest_severity`, and `checks_run`.

Errors are JSON with a stable shape,
`{"error": {"code": ..., "message": ...}}`: 400 for a body that is
not JSON or not an object, 413 past the 256 KB manifest cap, 422
for a manifest with no tools, resources, or prompts lists to audit.

## Tests

```bash
pip install pytest httpx
python -m pytest playground/tests -q
```

11 tests: the happy paths, the clean manifest, every error shape,
and a parity test asserting the API returns exactly what
`audit_server()` returns in-process.

## Honest limits

- Stateless by design. Manifests are audited in memory and
  forgotten. Nothing is stored or logged, which also means there is
  no history, no sharing link, and no accounts. Sharing links are a
  frontend concern (the manifest travels in the URL), not a reason
  to start keeping people's manifests on a server.
- No authentication and no per-IP rate limiting yet. Fine for a
  demo on a platform with its own edge controls; add both before
  exposing this on the open internet under your own domain.
- The bind defaults to 127.0.0.1. `HOST` and `PORT` come from the
  environment; set `HOST=0.0.0.0` only inside a container or Space
  that is meant to be reached.

Full notes: [docs/playground.md](../docs/playground.md).
