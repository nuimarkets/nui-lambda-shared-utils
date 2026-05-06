"""
Measure import-time cost of common entry points into ``nui_shared_utils``.

Runs ``python -X importtime -c "import <name>"`` in a fresh subprocess for each
entry point, parses the cumulative timings emitted on stderr, and prints a
summary table. Use before/after performance changes (lazy imports, dependency
shuffles) to confirm the impact on Lambda cold-start init.

Usage:
    python scripts/bench_imports.py
    python scripts/bench_imports.py --runs 3            # average over 3 runs
    python scripts/bench_imports.py --out out.json      # machine-readable
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import subprocess
import sys
from pathlib import Path

ENTRY_POINTS = [
    "nui_shared_utils",
    "nui_shared_utils.config",
    "nui_shared_utils.secrets_helper",
    "nui_shared_utils.jwt_auth",
    "nui_shared_utils.powertools_helpers",
    "nui_shared_utils.cloudwatch_metrics",
]

# Modules whose cumulative time we want to highlight per run, when present.
WATCH_MODULES = ["boto3", "botocore", "nui_shared_utils", "nui_shared_utils.secrets_helper"]

LINE_RE = re.compile(r"^import time:\s+(\d+)\s+\|\s+(\d+)\s+\|\s+(.+?)\s*$")


def measure(entry: str) -> dict:
    """Run a single ``python -X importtime`` invocation and parse the output."""
    proc = subprocess.run(
        [sys.executable, "-X", "importtime", "-c", f"import {entry}"],
        capture_output=True,
        text=True,
        check=True,
    )
    cumulative_us: dict[str, int] = {}
    for line in proc.stderr.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        # Strip leading nesting whitespace from the module name.
        module = m.group(3).strip()
        cum = int(m.group(2))
        # Last occurrence wins; importtime emits one final line per module load.
        cumulative_us[module] = cum
    return cumulative_us


def average_runs(entry: str, runs: int) -> dict:
    samples: list[dict[str, int]] = [measure(entry) for _ in range(runs)]
    averaged: dict[str, float] = {}
    keys = set().union(*(s.keys() for s in samples))
    for k in keys:
        vals = [s.get(k, 0) for s in samples]
        averaged[k] = statistics.mean(vals)
    return averaged


def fmt_ms(microseconds: float) -> str:
    return f"{microseconds / 1000:7.1f} ms"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=1, help="Number of runs per entry point (averaged)")
    parser.add_argument("--out", type=Path, default=None, help="Write raw results as JSON to this path")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error(f"--runs must be a positive integer, got {args.runs}")

    print(f"Python: {sys.version.split()[0]}    Runs per entry: {args.runs}")
    print()

    results: dict[str, dict[str, float]] = {}
    for entry in ENTRY_POINTS:
        cumulative = average_runs(entry, args.runs)
        results[entry] = cumulative

        total = cumulative.get(entry, 0)
        print(f"=== import {entry}")
        print(f"    cumulative: {fmt_ms(total)}")
        for watched in WATCH_MODULES:
            if watched in cumulative and watched != entry:
                print(f"      {watched:40s}{fmt_ms(cumulative[watched])}")
        print()

    if args.out:
        args.out.write_text(json.dumps(results, indent=2, sort_keys=True))
        print(f"Wrote raw results to {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
