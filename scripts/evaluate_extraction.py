from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.extract import extract_entities, extract_numeric_conditions, validate_numeric_hit


def _round_value(value: Any) -> float | None:
    if value is None:
        return None
    return round(float(value), 6)


def _entity_key(item: dict[str, Any]) -> tuple[str, str]:
    return (item["type"], item["canonical"])


def _numeric_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        item.get("property"),
        item.get("comparator"),
        _round_value(item.get("value")),
        _round_value(item.get("min_value")),
        _round_value(item.get("max_value")),
        item.get("unit"),
        item.get("validation_status", "valid"),
    )


def _relation_key(item: dict[str, Any]) -> tuple[str | None, str | None]:
    return (item.get("predicate"), item.get("property"))


def _score(expected: set[tuple[Any, ...]], actual: set[tuple[Any, ...]]) -> dict[str, Any]:
    true_positive = len(expected & actual)
    false_positive = len(actual - expected)
    false_negative = len(expected - actual)
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / max(1, true_positive + false_negative)
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {
        "tp": true_positive,
        "fp": false_positive,
        "fn": false_negative,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "missing": sorted(expected - actual, key=repr),
        "extra": sorted(actual - expected, key=repr),
    }


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    text = case["text"]
    actual_entities = {_entity_key({"type": hit.type, "canonical": hit.canonical}) for hit in extract_entities(text)}
    expected_entities = {_entity_key(item) for item in case.get("expected_entities", [])}

    actual_numeric = set()
    actual_relations = set()
    for hit in extract_numeric_conditions(text):
        validation_status, _warnings = validate_numeric_hit(hit)
        actual_numeric.add(
            _numeric_key(
                {
                    "property": hit.property,
                    "comparator": hit.comparator,
                    "value": hit.value,
                    "min_value": hit.min_value,
                    "max_value": hit.max_value,
                    "unit": hit.unit,
                    "validation_status": validation_status,
                }
            )
        )
        actual_relations.add(_relation_key({"predicate": "has_numeric_condition", "property": hit.property}))
    expected_numeric = {_numeric_key(item) for item in case.get("expected_numeric", [])}
    expected_relation_specs = case.get("expected_relations")
    if expected_relation_specs is None:
        expected_relation_specs = [
            {"predicate": "has_numeric_condition", "property": item.get("property")}
            for item in case.get("expected_numeric", [])
            if item.get("property")
        ]
    expected_relations = {_relation_key(item) for item in expected_relation_specs}

    entity_score = _score(expected_entities, actual_entities)
    numeric_score = _score(expected_numeric, actual_numeric)
    relation_score = _score(expected_relations, actual_relations)
    return {
        "id": case["id"],
        "passed": entity_score["fn"] == 0 and numeric_score["fn"] == 0 and relation_score["fn"] == 0,
        "entities": entity_score,
        "numeric": numeric_score,
        "relations": relation_score,
    }


def _aggregate(results: list[dict[str, Any]], key: str) -> dict[str, Any]:
    tp = sum(item[key]["tp"] for item in results)
    fp = sum(item[key]["fp"] for item in results)
    fn = sum(item[key]["fn"] for item in results)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate entity and numeric extraction against a gold JSON set.")
    parser.add_argument("--gold", type=Path, default=PROJECT_ROOT / "data/evaluation/extraction_gold.json")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--min-entity-recall", type=float, default=1.0)
    parser.add_argument("--min-numeric-recall", type=float, default=1.0)
    parser.add_argument("--min-relation-f1", type=float, default=1.0)
    args = parser.parse_args()

    cases = json.loads(args.gold.read_text(encoding="utf-8"))
    results = [evaluate_case(case) for case in cases]
    entity_summary = _aggregate(results, "entities")
    numeric_summary = _aggregate(results, "numeric")
    relation_summary = _aggregate(results, "relations")
    summary = {
        "passed": sum(1 for item in results if item["passed"]),
        "total": len(results),
        "pass_rate": round(sum(1 for item in results if item["passed"]) / max(1, len(results)), 3),
        "entities": entity_summary,
        "numeric": numeric_summary,
        "relations": relation_summary,
        "thresholds": {
            "min_entity_recall": args.min_entity_recall,
            "min_numeric_recall": args.min_numeric_recall,
            "min_relation_f1": args.min_relation_f1,
        },
        "thresholds_passed": (
            entity_summary["recall"] >= args.min_entity_recall
            and numeric_summary["recall"] >= args.min_numeric_recall
            and relation_summary["f1"] >= args.min_relation_f1
        ),
        "results": results,
    }
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(
            f"Cases {summary['passed']}/{summary['total']}; "
            f"entity F1={entity_summary['f1']:.3f}; numeric F1={numeric_summary['f1']:.3f}; "
            f"relation F1={relation_summary['f1']:.3f}"
        )
        for item in results:
            status = "PASS" if item["passed"] else "FAIL"
            print(
                f"{status} {item['id']} entities={item['entities']} "
                f"numeric={item['numeric']} relations={item['relations']}"
            )
    if not summary["thresholds_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
