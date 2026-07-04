from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from statistics import median
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import connect, ensure_demo_db
from app.models import SearchRequest
from app.search import run_search


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * pct
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _summary(values: list[float]) -> dict[str, float]:
    return {
        "count": len(values),
        "p50_ms": round(median(values), 2) if values else 0.0,
        "p95_ms": round(percentile(values, 0.95), 2),
        "max_ms": round(max(values), 2) if values else 0.0,
    }


def benchmark_cases(cases: list[dict[str, Any]], iterations: int, top_k: int, warmup: bool = True) -> dict[str, Any]:
    timings: dict[str, list[float]] = {case["id"]: [] for case in cases}
    with connect() as conn:
        if warmup:
            for case in cases:
                run_search(conn, SearchRequest(query=case["query"], top_k=top_k), role="researcher")
        for _ in range(iterations):
            for case in cases:
                start = time.perf_counter()
                result = run_search(conn, SearchRequest(query=case["query"], top_k=top_k), role="researcher")
                elapsed_ms = (time.perf_counter() - start) * 1000
                timings[case["id"]].append(elapsed_ms)
                if not result.get("sources"):
                    raise RuntimeError(f"Query returned no sources: {case['id']}")
    all_values = [value for values in timings.values() for value in values]
    return {
        "iterations": iterations,
        "top_k": top_k,
        "queries": {case_id: _summary(values) for case_id, values in timings.items()},
        "overall": _summary(all_values),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark local search latency over gold queries.")
    parser.add_argument("--gold", type=Path, default=PROJECT_ROOT / "data/evaluation/gold_queries.json")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--top-k", type=int, default=8)
    parser.add_argument("--no-warmup", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.iterations < 1:
        raise SystemExit("--iterations must be >= 1")
    ensure_demo_db()
    cases = json.loads(args.gold.read_text(encoding="utf-8"))
    summary = benchmark_cases(cases, iterations=args.iterations, top_k=args.top_k, warmup=not args.no_warmup)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return
    print(f"Search benchmark: iterations={summary['iterations']} top_k={summary['top_k']}")
    print(f"Overall: {summary['overall']}")
    for case_id, item in summary["queries"].items():
        print(f"{case_id}: {item}")


if __name__ == "__main__":
    main()
