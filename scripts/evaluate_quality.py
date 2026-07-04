from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import connect, ensure_demo_db
from app.models import SearchRequest
from app.search import run_search
from app.synthesize import attach_answer


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return round(numerator / denominator, 3)


def _source_recall(titles: list[str], expected_contains: list[str]) -> dict[str, object]:
    hits = [
        expected
        for expected in expected_contains
        if any(expected.lower() in title.lower() for title in titles)
    ]
    return {
        "expected": len(expected_contains),
        "hits": len(hits),
        "missing": [expected for expected in expected_contains if expected not in hits],
        "recall": _ratio(len(hits), len(expected_contains)),
    }


def _has_span(item: dict) -> bool:
    span = item.get("span") or []
    return len(span) == 2 and span[0] is not None and span[1] is not None


def _evidence_metrics(result: dict) -> dict[str, object]:
    fact_items = result.get("evidence_pack", {}).get("facts", [])
    source_items = result.get("evidence_pack", {}).get("source_snippets", [])
    trace_supported = [
        item
        for item in fact_items
        if item.get("source_title") and item.get("document_id") and item.get("evidence") and _has_span(item)
    ]
    locator_supported = [item for item in trace_supported if item.get("locator")]
    snippet_supported = [
        item
        for item in source_items
        if item.get("title") and item.get("document_id") and item.get("snippet")
    ]
    return {
        "evidence_fact_count": len(fact_items),
        "evidence_trace_supported": len(trace_supported),
        "evidence_trace_coverage": _ratio(len(trace_supported), len(fact_items)),
        "evidence_locator_supported": len(locator_supported),
        "evidence_locator_coverage": _ratio(len(locator_supported), len(fact_items)),
        "source_snippet_count": len(source_items),
        "source_snippet_coverage": _ratio(len(snippet_supported), len(source_items)),
    }


def _answer_metrics(result: dict) -> dict[str, object]:
    payload = attach_answer(result)
    answer = payload.get("answer_markdown", "")
    fact_source_titles = sorted(
        {
            item["source_title"]
            for item in result.get("evidence_pack", {}).get("facts", [])
            if item.get("source_title")
        }
    )
    cited_titles = [title for title in fact_source_titles if title in answer]
    return {
        "answer_expected_source_citations": len(fact_source_titles),
        "answer_cited_sources": len(cited_titles),
        "answer_citation_coverage": _ratio(len(cited_titles), len(fact_source_titles)),
        "unsupported_answer_markers": answer.count("без источника"),
    }


def evaluate_case(
    conn,
    case: dict,
    *,
    default_top_k: int = 8,
    min_retrieval_recall_at_k: float = 1.0,
    min_evidence_trace_coverage: float = 1.0,
    min_answer_citation_coverage: float = 1.0,
) -> dict:
    top_k = int(case.get("top_k", default_top_k))
    result = run_search(conn, SearchRequest(query=case["query"], top_k=top_k), role="researcher")
    titles = [source.get("title", "") for source in result["sources"]]
    parsed = result["parsed_query"]
    source_metrics = _source_recall(titles, case.get("expected_source_contains", []))
    evidence_metrics = _evidence_metrics(result)
    answer_metrics = _answer_metrics(result)
    metrics = {
        "retrieval_recall_at_k": source_metrics["recall"],
        f"retrieval_recall_at_{top_k}": source_metrics["recall"],
        "evidence_trace_coverage": evidence_metrics["evidence_trace_coverage"],
        "evidence_locator_coverage": evidence_metrics["evidence_locator_coverage"],
        "source_snippet_coverage": evidence_metrics["source_snippet_coverage"],
        "answer_citation_coverage": answer_metrics["answer_citation_coverage"],
        "unsupported_answer_markers": answer_metrics["unsupported_answer_markers"],
    }
    retrieval_threshold = float(case.get("min_retrieval_recall_at_k", min_retrieval_recall_at_k))
    evidence_threshold = float(case.get("min_evidence_trace_coverage", min_evidence_trace_coverage))
    answer_threshold = float(case.get("min_answer_citation_coverage", min_answer_citation_coverage))
    checks = {
        "min_sources": len(result["sources"]) >= case.get("min_sources", 0),
        "min_facts": len(result["facts"]) >= case.get("min_facts", 0),
        "min_gaps": len(result["gaps"]) >= case.get("min_gaps", 0),
        "source_contains": source_metrics["recall"] == 1.0,
        "processes": set(case.get("expected_processes", [])).issubset(set(parsed.get("processes") or [])),
        "materials": set(case.get("expected_materials", [])).issubset(set(parsed.get("materials") or [])),
        "retrieval_recall_at_k": source_metrics["recall"] >= retrieval_threshold,
        "evidence_trace_coverage": evidence_metrics["evidence_trace_coverage"] >= evidence_threshold,
        "answer_citation_coverage": answer_metrics["answer_citation_coverage"] >= answer_threshold,
        "answer_has_no_unsupported_markers": answer_metrics["unsupported_answer_markers"] == 0,
    }
    return {
        "id": case["id"],
        "passed": all(checks.values()),
        "checks": checks,
        "metrics": metrics,
        "thresholds": {
            "top_k": top_k,
            "min_retrieval_recall_at_k": retrieval_threshold,
            "min_evidence_trace_coverage": evidence_threshold,
            "min_answer_citation_coverage": answer_threshold,
        },
        "source_recall": source_metrics,
        "evidence": evidence_metrics,
        "answer": answer_metrics,
        "sources": titles,
        "facts": len(result["facts"]),
        "experiments": len(result["experiments"]),
        "gaps": result["gaps"],
        "parsed_query": parsed,
    }


def _avg(results: list[dict], metric: str) -> float:
    return round(sum(float(item["metrics"].get(metric, 0.0)) for item in results) / max(1, len(results)), 3)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate demo query understanding and retrieval quality.")
    parser.add_argument("--gold", type=Path, default=PROJECT_ROOT / "data/evaluation/gold_queries.json")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--top-k", type=int, default=8)
    parser.add_argument("--min-retrieval-recall-at-k", type=float, default=1.0)
    parser.add_argument("--min-evidence-trace-coverage", type=float, default=1.0)
    parser.add_argument("--min-answer-citation-coverage", type=float, default=1.0)
    args = parser.parse_args()

    ensure_demo_db()
    cases = json.loads(args.gold.read_text(encoding="utf-8"))
    with connect() as conn:
        results = [
            evaluate_case(
                conn,
                case,
                default_top_k=args.top_k,
                min_retrieval_recall_at_k=args.min_retrieval_recall_at_k,
                min_evidence_trace_coverage=args.min_evidence_trace_coverage,
                min_answer_citation_coverage=args.min_answer_citation_coverage,
            )
            for case in cases
        ]
    summary = {
        "passed": sum(1 for item in results if item["passed"]),
        "total": len(results),
        "pass_rate": round(sum(1 for item in results if item["passed"]) / max(1, len(results)), 3),
        "metrics": {
            "retrieval_recall_at_k": _avg(results, "retrieval_recall_at_k"),
            "evidence_trace_coverage": _avg(results, "evidence_trace_coverage"),
            "evidence_locator_coverage": _avg(results, "evidence_locator_coverage"),
            "source_snippet_coverage": _avg(results, "source_snippet_coverage"),
            "answer_citation_coverage": _avg(results, "answer_citation_coverage"),
            "unsupported_answer_markers": sum(
                int(item["metrics"].get("unsupported_answer_markers", 0)) for item in results
            ),
        },
        "thresholds": {
            "top_k": args.top_k,
            "min_retrieval_recall_at_k": args.min_retrieval_recall_at_k,
            "min_evidence_trace_coverage": args.min_evidence_trace_coverage,
            "min_answer_citation_coverage": args.min_answer_citation_coverage,
        },
        "thresholds_passed": all(item["passed"] for item in results),
        "results": results,
    }
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return
    print(
        f"Passed {summary['passed']}/{summary['total']} ({summary['pass_rate']:.3f}); "
        f"retrieval recall@k={summary['metrics']['retrieval_recall_at_k']:.3f}; "
        f"evidence trace={summary['metrics']['evidence_trace_coverage']:.3f}; "
        f"answer citations={summary['metrics']['answer_citation_coverage']:.3f}"
    )
    for item in results:
        status = "PASS" if item["passed"] else "FAIL"
        print(f"{status} {item['id']}: checks={item['checks']} metrics={item['metrics']}")


if __name__ == "__main__":
    main()
