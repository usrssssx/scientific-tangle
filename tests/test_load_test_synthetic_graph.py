import sqlite3
from pathlib import Path

from app.db import create_schema
from scripts.load_test_synthetic_graph import (
    build_synthetic_graph,
    percentile,
    run_load_test,
    synthetic_start_ids,
    timing_summary,
)


def test_percentile_and_timing_summary():
    assert percentile([10.0, 20.0, 30.0], 0.95) == 29.0
    assert timing_summary([10.0, 20.0, 30.0]) == {
        "count": 3,
        "p50_ms": 20.0,
        "p95_ms": 29.0,
        "max_ms": 30.0,
    }


def test_synthetic_start_ids_are_spread_across_entity_range():
    assert synthetic_start_ids(100, 4) == [1, 26, 51, 76]
    assert synthetic_start_ids(3, 5) == [1, 2, 3, 3, 3]


def test_build_synthetic_graph_creates_counts_and_indexes(tmp_path):
    db_path = tmp_path / "synthetic.sqlite"

    build = build_synthetic_graph(db_path, entity_count=120, fact_count=90, edge_fanout=2, batch_size=25)

    with sqlite3.connect(db_path) as conn:
        counts = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("sources", "entities", "facts", "graph_edges")
        }
        indexes = {row[1] for row in conn.execute("PRAGMA index_list(graph_edges)").fetchall()}

    assert build["entities"] == 120
    assert build["facts"] == 90
    assert build["graph_edges"] == 240
    assert counts == {"sources": 1, "entities": 120, "facts": 90, "graph_edges": 240}
    assert {"idx_graph_edges_subject", "idx_graph_edges_object"}.issubset(indexes)


def test_run_load_test_smoke_profile_passes_target(tmp_path):
    db_path = tmp_path / "smoke.sqlite"

    report = run_load_test(
        db_path,
        entity_count=300,
        fact_count=300,
        edge_fanout=2,
        query_count=4,
        depth=4,
        target_seconds=5.0,
        batch_size=50,
    )

    assert report["ok"] is True
    assert report["counts"]["entities"] == 300
    assert report["counts"]["graph_edges"] == 600
    assert report["benchmarks"]["graph_traversal"]["min_reached_nodes"] > 1
    assert report["benchmarks"]["graph_traversal"]["p95_ms"] < 5000


def test_application_schema_has_graph_and_fact_lookup_indexes():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    create_schema(conn)

    graph_indexes = {row["name"] for row in conn.execute("PRAGMA index_list(graph_edges)").fetchall()}
    fact_indexes = {row["name"] for row in conn.execute("PRAGMA index_list(facts)").fetchall()}

    assert {"idx_graph_edges_subject", "idx_graph_edges_object", "idx_graph_edges_predicate"}.issubset(graph_indexes)
    assert {"idx_facts_subject", "idx_facts_object"}.issubset(fact_indexes)
