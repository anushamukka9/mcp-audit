# CI usage

Audit your MCP server on every pull request. Two patterns work well.

## Fail the build on new issues

```yaml
- name: Audit MCP manifest
  run: |
    pip install mcp-audit
    mcp-audit scan path/to/manifest.json --fail-on high
```

The step exits 1 when any finding meets the threshold, which fails the job.
Start with `--fail-on high` (or `never` for a first run on an existing
server), then tighten it as you clear the backlog.

## Upload SARIF to code scanning

```yaml
- name: Audit MCP manifest
  run: |
    pip install mcp-audit
    mcp-audit scan path/to/manifest.json --format sarif --fail-on never > mcp-audit.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-audit.sarif
```

Findings show up under the repository's Security tab, next to your other
code-scanning alerts. Critical and high findings map to SARIF `error`,
medium to `warning`, low to `note`.

## Keep a policy file in the repo

Check a `mcp-audit-policy.json` into the server repo and reference it from
CI so allowlist decisions are reviewed like code:

```yaml
mcp-audit scan manifest.json --config mcp-audit-policy.json --fail-on high
```

See [configuration](configuration.md) for the file format.
