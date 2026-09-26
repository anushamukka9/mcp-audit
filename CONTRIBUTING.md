# Contributing

Bug reports and pull requests are welcome. A few ground rules so the
project stays small and honest.

## What belongs here

- New checks for real MCP server security issues, with tests and a labeled
  benchmark case.
- Better detection for existing checks, as long as it stays deterministic.
- Docs fixes and clearer remediation advice.

## What does not

- Anything that calls a model or the network at scan time. Deterministic is
  the whole point.
- Checks that need to execute the server. mcp-audit reads manifests.

## How to contribute

1. Fork, branch off `develop`, and keep the change focused.
2. Add tests in `tests/` and a labeled case in `benchmarks/` if you touch a
   check. Run `pytest -q` and `python -m mcp_audit.benchmark`; both must be
   green, and the README benchmark table must match the new numbers.
3. Run `ruff check src tests` and `ruff format --check src tests`.
4. Write the check's limitations in its docstring. Every check has blind
   spots; document yours.
5. Open a PR against `develop` with a plain description of what changed and
   why.

## Style

- No em-dashes anywhere. Not in code, not in docs, not in commit messages.
- Line length 100, enforced by ruff.
- Findings explain the problem in plain language and always include
  remediation advice. A finding without a fix is just anxiety.
