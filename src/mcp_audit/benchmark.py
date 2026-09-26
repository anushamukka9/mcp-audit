"""Benchmark runner: python -m mcp_audit.benchmark

Each file in benchmarks/ is a labeled manifest:

    {
        "name": "shell-tool",
        "manifest": { ... },
        "expected_checks": ["broad_tool", "missing_auth"]
    }

The runner audits every manifest with the default checks and scores each
check on precision/recall against the labels. The numbers this prints are
the numbers in the README.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import audit_server, default_checks

BENCHMARK_DIR = Path(__file__).resolve().parent.parent.parent / "benchmarks"


def load_cases() -> list[dict]:
    cases = []
    for path in sorted(BENCHMARK_DIR.glob("*.json")):
        with open(path, encoding="utf-8") as fh:
            cases.append(json.load(fh))
    return cases


def run() -> dict[str, dict[str, float | int]]:
    checks = default_checks()
    stats = {c.id: {"tp": 0, "fp": 0, "fn": 0, "n": 0} for c in checks}
    for case in load_cases():
        expected = set(case.get("expected_checks", []))
        report = audit_server(case["manifest"])
        predicted = {f.check_id for f in report.findings}
        for check_id in stats:
            hit_expected = check_id in expected
            hit_predicted = check_id in predicted
            if hit_expected and hit_predicted:
                stats[check_id]["tp"] += 1
            elif hit_predicted:
                stats[check_id]["fp"] += 1
            elif hit_expected:
                stats[check_id]["fn"] += 1
            if hit_expected or hit_predicted:
                stats[check_id]["n"] += 1
    results = {}
    for check_id, s in stats.items():
        precision = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) else 1.0
        recall = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) else 1.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        results[check_id] = {"n": s["n"], "precision": precision, "recall": recall, "f1": f1}
    return results


def main() -> None:
    results = run()
    print(f"{'check':28} {'n':>3} {'precision':>9} {'recall':>7} {'f1':>6}")
    totals = {"tp": 0.0, "fp": 0.0, "fn": 0.0, "n": 0}
    for check_id, r in results.items():
        prec = f"{r['precision']:.2f}"
        rec = f"{r['recall']:.2f}"
        f1 = f"{r['f1']:.2f}"
        print(f"{check_id:28} {r['n']:>3} {prec:>9} {rec:>7} {f1:>6}")
        totals["n"] += r["n"]
    precisions = [r["precision"] for r in results.values()]
    recalls = [r["recall"] for r in results.values()]
    f1s = [r["f1"] for r in results.values()]
    n = len(results)
    avg_p = sum(precisions) / n
    avg_r = sum(recalls) / n
    avg_f1 = sum(f1s) / n
    print(f"{'macro-average':28} {'':>3} {avg_p:>9.2f} {avg_r:>7.2f} {avg_f1:>6.2f}")
    cases = len(load_cases())
    print(f"cases scored: {int(totals['n'])} check-activations across {cases} manifests")


if __name__ == "__main__":
    main()
