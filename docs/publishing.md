# Publishing to PyPI

mcp-audit publishes through the trusted-publisher workflow in
`.github/workflows/publish.yml`. No API tokens to manage.

## One-time setup (about two minutes)

1. Create the project on PyPI (or skip this; the first trusted-publisher
   upload creates it).
2. On PyPI, open the project settings, go to Publishing, and add a GitHub
   Actions publisher for `anushamukka9/mcp-audit` with workflow
   `publish.yml` and environment `pypi`.
3. Do the same on TestPyPI with environment `testpypi` if you want the dry
   run path.

## Releasing

1. Bump `__version__` in `src/mcp_audit/__init__.py` and the `version` in
   `pyproject.toml` (there is a test that fails if they drift).
2. Push to `develop`, open a PR, merge.
3. Draft a GitHub Release from `develop`. Publishing to real PyPI happens
   only from a published release.

## Dry runs

The workflow also runs on manual dispatch and publishes to TestPyPI only,
so you can exercise the whole pipeline without touching real PyPI:
Actions > Publish to PyPI > Run workflow.
