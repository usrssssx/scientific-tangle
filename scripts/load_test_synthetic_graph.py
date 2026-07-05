from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path
from statistics import median
from typing import Any, Iterable, Iterator


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


PROFILES = {
    "smoke": {
        "entities": 10_000,
        "facts": 10_000,
        "edge_fanout": 2,
        "queries": 8,
        "depth": 4,
        "target_seconds": 5.0,
    },
    "pilot-1m": {
        "entities": 1_000_000,
        "facts": 1_000_000,
        "edge_fanout": 2,
        "queries": 25,
        "depth": 4,
        "target_seconds": 5.0,
    },
}
ENTITY_TYPES = ("Material", "Process", "Equipment", "Property", "Experiment", "Publication", "Expert", "Facility")
EDGE_PREDICATES = ("uses_material", "operates_at_condition", "produces_output", "described_in")


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


def timing_summary(values: list[float]) -> dict[str, float | int]:
    return {
        "count": len(values),
        "p50_ms": round(median(values), 2) if values else 0.0,
        "p95_ms": round(percentile(values, 0.95), 2),
        "max_ms": round(max(values), 2) if values else 0.0,
    }


def batched(items: Iterable[tuple[Any, ...]], batch_size: int) -> Iterator[list[tuple[Any, ...]]]:
    batch: list[tuple[Any, ...]] = []
    for item in items:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def create_load_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        DROP TABLE IF EXISTS graph_edges;
        DROP TABLE IF EXISTS facts;
        DROP TABLE IF EXISTS entities;
        DROP TABLE IF EXISTS sources;

        CREATE TABLE sources (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            source_type TEXT NOT NULL,
            language TEXT,
            geography TEXT,
            year INTEGER,
            reliability_score REAL DEFAULT 0.5,
            confidentiality TEXT DEFAULT 'internal',
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE entities (
            id INTEGER PRIMARY KEY,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            aliases_json TEXT DEFAULT '[]',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(type, normalized_name)
        );

        CREATE TABLE facts (
            id INTEGER PRIMARY KEY,
            source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
            subject_id INTEGER REFERENCES entities(id) ON DELETE SET NULL,
            predicate TEXT NOT NULL,
            object_id INTEGER REFERENCES entities(id) ON DELETE SET NULL,
            property TEXT,
            comparator TEXT,
            numeric_value REAL,
            min_value REAL,
            max_value REAL,
            unit TEXT,
            value_text TEXT,
            confidence REAL DEFAULT 0.5,
            extraction_confidence REAL DEFAULT 0.5,
            validation_status TEXT DEFAULT 'valid',
            validation_warnings_json TEXT DEFAULT '[]',
            status TEXT DEFAULT 'candidate',
            version INTEGER DEFAULT 1,
            evidence TEXT,
            evidence_locator TEXT,
            extractor_version TEXT DEFAULT 'synthetic-load-v1',
            asserted_by TEXT DEFAULT 'load-test',
            asserted_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE graph_edges (
            id INTEGER PRIMARY KEY,
            source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
            subject_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            predicate TEXT NOT NULL,
            object_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            confidence REAL DEFAULT 0.5,
            evidence TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(source_id, subject_id, predicate, object_id, evidence)
        );
        """
    )


def create_load_indexes(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_entities_norm ON entities(normalized_name);
        CREATE INDEX IF NOT EXISTS idx_facts_subject ON facts(subject_id);
        CREATE INDEX IF NOT EXISTS idx_facts_object ON facts(object_id);
        CREATE INDEX IF NOT EXISTS idx_facts_status_confidence ON facts(status, confidence DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_facts_numeric ON facts(property, min_value, max_value, numeric_value, unit);
        CREATE INDEX IF NOT EXISTS idx_graph_edges_subject ON graph_edges(subject_id);
        CREATE INDEX IF NOT EXISTS idx_graph_edges_object ON graph_edges(object_id);
        CREATE INDEX IF NOT EXISTS idx_graph_edges_predicate ON graph_edges(predicate);
        CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_id);
        """
    )


def entity_rows(entity_count: int) -> Iterator[tuple[int, str, str, str, str]]:
    for entity_id in range(1, entity_count + 1):
        entity_type = ENTITY_TYPES[(entity_id - 1) % len(ENTITY_TYPES)]
        yield (
            entity_id,
            entity_type,
            f"{entity_type} {entity_id:09d}",
            f"{entity_type.lower()}_{entity_id:09d}",
            "[]",
        )


def fact_rows(entity_count: int, fact_count: int) -> Iterator[tuple[Any, ...]]:
    for fact_id in range(1, fact_count + 1):
        subject_id = ((fact_id - 1) % entity_count) + 1
        object_id = (subject_id % entity_count) + 1
        value = float((fact_id % 10_000) / 10)
        yield (
            fact_id,
            1,
            subject_id,
            "has_synthetic_property",
            object_id,
            "synthetic_property",
            "between",
            value,
            value,
            value + 1.0,
            "unit",
            f"{value:.1f}-{value + 1.0:.1f} unit",
            0.75,
            0.8,
            "valid",
            "candidate",
            f"synthetic evidence {fact_id}",
            "chunk 1",
        )


def edge_rows(entity_count: int, edge_fanout: int) -> Iterator[tuple[Any, ...]]:
    edge_id = 1
    offsets = [1 + index * 17 for index in range(edge_fanout)]
    for subject_id in range(1, entity_count + 1):
        for index, offset in enumerate(offsets):
            object_id = ((subject_id + offset - 1) % entity_count) + 1
            predicate = EDGE_PREDICATES[index % len(EDGE_PREDICATES)]
            yield (
                edge_id,
                1,
                subject_id,
                predicate,
                object_id,
                0.7,
                f"synthetic edge {subject_id}->{object_id}",
            )
            edge_id += 1


def _insert_batches(conn: sqlite3.Connection, sql: str, rows: Iterable[tuple[Any, ...]], batch_size: int) -> int:
    inserted = 0
    for batch in batched(rows, batch_size):
        conn.executemany(sql, batch)
        inserted += len(batch)
    return inserted


def build_synthetic_graph(
    db_path: Path,
    *,
    entity_count: int,
    fact_count: int,
    edge_fanout: int,
    batch_size: int = 10_000,
    reset: bool = True,
) -> dict[str, Any]:
    db_path = db_path.expanduser().resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if reset:
        db_path.unlink(missing_ok=True)
    started = time.perf_counter()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA cache_size = -200000")
        create_load_schema(conn)
        conn.execute(
            """
            INSERT INTO sources(id, title, source_type, language, geography, year, reliability_score, confidentiality, metadata_json)
            VALUES (1, 'Synthetic 1M graph load source', 'synthetic_load', 'en', 'global', 2026, 0.8, 'internal', '{}')
            """
        )
        inserted_entities = _insert_batches(
            conn,
            "INSERT INTO entities(id, type, name, normalized_name, aliases_json) VALUES (?, ?, ?, ?, ?)",
            entity_rows(entity_count),
            batch_size,
        )
        inserted_facts = _insert_batches(
            conn,
            """
            INSERT INTO facts(
                id, source_id, subject_id, predicate, object_id, property, comparator, numeric_value,
                min_value, max_value, unit, value_text, confidence, extraction_confidence,
                validation_status, status, evidence, evidence_locator
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            fact_rows(entity_count, fact_count),
            batch_size,
        )
        inserted_edges = _insert_batches(
            conn,
            "INSERT INTO graph_edges(id, source_id, subject_id, predicate, object_id, confidence, evidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
            edge_rows(entity_count, edge_fanout),
            batch_size,
        )
        index_started = time.perf_counter()
        create_load_indexes(conn)
        conn.commit()
        index_seconds = time.perf_counter() - index_started
    return {
        "database": str(db_path),
        "entities": inserted_entities,
        "facts": inserted_facts,
        "graph_edges": inserted_edges,
        "edge_fanout": edge_fanout,
        "build_seconds": round(time.perf_counter() - started, 2),
        "index_seconds": round(index_seconds, 2),
        "size_mb": round(db_path.stat().st_size / (1024 * 1024), 2),
    }


def synthetic_start_ids(entity_count: int, query_count: int) -> list[int]:
    if query_count <= 0:
        return []
    step = max(1, entity_count // query_count)
    return [min(entity_count, 1 + index * step) for index in range(query_count)]


def benchmark_graph(conn: sqlite3.Connection, start_ids: list[int], depth: int) -> dict[str, Any]:
    timings: list[float] = []
    reached: list[int] = []
    sql = """
    WITH RECURSIVE frontier(id, depth) AS (
        SELECT ? AS id, 0 AS depth
        UNION
        SELECT
            CASE WHEN ge.subject_id = frontier.id THEN ge.object_id ELSE ge.subject_id END AS id,
            frontier.depth + 1 AS depth
        FROM frontier
        JOIN graph_edges ge ON ge.subject_id = frontier.id OR ge.object_id = frontier.id
        WHERE frontier.depth < ?
    )
    SELECT COUNT(DISTINCT id) FROM frontier
    """
    for start_id in start_ids:
        started = time.perf_counter()
        count = int(conn.execute(sql, (start_id, depth)).fetchone()[0])
        timings.append((time.perf_counter() - started) * 1000)
        reached.append(count)
    summary = timing_summary(timings)
    summary["min_reached_nodes"] = min(reached) if reached else 0
    summary["max_reached_nodes"] = max(reached) if reached else 0
    return summary


def benchmark_fact_lookup(conn: sqlite3.Connection, start_ids: list[int]) -> dict[str, Any]:
    timings: list[float] = []
    counts: list[int] = []
    sql = "SELECT COUNT(*) FROM facts WHERE subject_id = ? AND status = 'candidate'"
    for start_id in start_ids:
        started = time.perf_counter()
        count = int(conn.execute(sql, (start_id,)).fetchone()[0])
        timings.append((time.perf_counter() - started) * 1000)
        counts.append(count)
    summary = timing_summary(timings)
    summary["min_facts"] = min(counts) if counts else 0
    summary["max_facts"] = max(counts) if counts else 0
    return summary


def database_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {
        table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in ("sources", "entities", "facts", "graph_edges")
    }


def run_load_test(
    db_path: Path,
    *,
    entity_count: int,
    fact_count: int,
    edge_fanout: int,
    query_count: int,
    depth: int,
    target_seconds: float,
    batch_size: int = 10_000,
    skip_build: bool = False,
    reset: bool = True,
) -> dict[str, Any]:
    build = None
    if not skip_build:
        build = build_synthetic_graph(
            db_path,
            entity_count=entity_count,
            fact_count=fact_count,
            edge_fanout=edge_fanout,
            batch_size=batch_size,
            reset=reset,
        )
    started = time.perf_counter()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA cache_size = -200000")
        counts = database_counts(conn)
        start_ids = synthetic_start_ids(counts["entities"], query_count)
        graph = benchmark_graph(conn, start_ids, depth)
        facts = benchmark_fact_lookup(conn, start_ids)
    target_ms = target_seconds * 1000
    passed = bool(
        counts["entities"] >= entity_count
        and counts["facts"] >= fact_count
        and counts["graph_edges"] >= entity_count * edge_fanout
        and float(graph["p95_ms"]) <= target_ms
        and float(facts["p95_ms"]) <= target_ms
    )
    return {
        "ok": passed,
        "database": str(db_path.expanduser().resolve()),
        "target_seconds": target_seconds,
        "requested": {
            "entities": entity_count,
            "facts": fact_count,
            "edge_fanout": edge_fanout,
            "queries": query_count,
            "depth": depth,
        },
        "counts": counts,
        "build": build,
        "benchmarks": {
            "graph_traversal_depth": depth,
            "graph_traversal": graph,
            "fact_lookup": facts,
        },
        "elapsed_seconds": round(time.perf_counter() - started + (float(build["build_seconds"]) if build else 0.0), 2),
    }


def resolved_profile(name: str) -> dict[str, Any]:
    if name not in PROFILES:
        raise SystemExit(f"Unknown profile {name!r}. Choose one of: {', '.join(sorted(PROFILES))}")
    return dict(PROFILES[name])


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and benchmark a synthetic graph load profile.")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="smoke")
    parser.add_argument("--database", type=Path, default=PROJECT_ROOT / "data/load_tests/rdkg_synthetic.sqlite")
    parser.add_argument("--entities", type=int, default=None)
    parser.add_argument("--facts", type=int, default=None)
    parser.add_argument("--edge-fanout", type=int, default=None)
    parser.add_argument("--queries", type=int, default=None)
    parser.add_argument("--depth", type=int, default=None)
    parser.add_argument("--target-seconds", type=float, default=None)
    parser.add_argument("--batch-size", type=int, default=10_000)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--no-reset", action="store_true")
    parser.add_argument("--delete-after", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    profile = resolved_profile(args.profile)
    entity_count = int(args.entities if args.entities is not None else profile["entities"])
    fact_count = int(args.facts if args.facts is not None else profile["facts"])
    edge_fanout = int(args.edge_fanout if args.edge_fanout is not None else profile["edge_fanout"])
    query_count = int(args.queries if args.queries is not None else profile["queries"])
    depth = int(args.depth if args.depth is not None else profile["depth"])
    target_seconds = float(args.target_seconds if args.target_seconds is not None else profile["target_seconds"])
    for name, value in {
        "entities": entity_count,
        "facts": fact_count,
        "edge_fanout": edge_fanout,
        "queries": query_count,
        "depth": depth,
        "batch_size": args.batch_size,
    }.items():
        if value < 1:
            raise SystemExit(f"--{name.replace('_', '-')} must be >= 1")

    report = run_load_test(
        args.database,
        entity_count=entity_count,
        fact_count=fact_count,
        edge_fanout=edge_fanout,
        query_count=query_count,
        depth=depth,
        target_seconds=target_seconds,
        batch_size=args.batch_size,
        skip_build=args.skip_build,
        reset=not args.no_reset,
    )
    if args.delete_after:
        db_path = Path(report["database"])
        for suffix in ("", "-wal", "-shm"):
            Path(str(db_path) + suffix).unlink(missing_ok=True)
        report["deleted_after"] = True
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"Synthetic graph load test ok={report['ok']} target={target_seconds}s")
        print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
