from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path
from typing import Any

from .config import DATA_DIR, DICTIONARY_DIR, SAMPLE_DOCS_DIR, DB_PATH
from .db import (
    create_schema,
    insert_document_chunk,
    insert_edge,
    insert_fact,
    insert_source,
    upsert_entity,
)
from .extract import (
    EXTRACTOR_VERSION,
    chunk_text_with_locations,
    extract_entities,
    extract_numeric_conditions,
    load_domain_terms,
    read_document_text,
    validate_numeric_hit,
)


def _entity_type_from_category(category: str) -> str:
    return {
        "materials": "Material",
        "processes": "Process",
        "equipment": "Equipment",
        "properties": "Property",
        "geography": "Geography",
    }.get(category, "Concept")


def seed_dictionary_entities(conn) -> None:
    terms = json.loads((DICTIONARY_DIR / "domain_terms.json").read_text(encoding="utf-8"))
    for category, items in terms.items():
        if not isinstance(items, dict):
            continue
        type_ = _entity_type_from_category(category)
        for canonical, aliases in items.items():
            upsert_entity(conn, type_, canonical, canonical, aliases)


def ingest_sample_documents(conn) -> dict[str, int]:
    terms = load_domain_terms()
    title_to_source_id: dict[str, int] = {}
    for path in sorted(SAMPLE_DOCS_DIR.glob("*")):
        if path.is_dir():
            continue
        metadata, body = read_document_text(path)
        metadata.setdefault("title", path.stem)
        metadata.setdefault("source_type", "document")
        metadata.setdefault("language", "ru")
        metadata.setdefault("reliability_score", 0.55)
        metadata.setdefault("confidentiality", "internal")
        abstract = body[:500]
        source_id = insert_source(conn, metadata, path=str(path), abstract=abstract)
        title_to_source_id[str(metadata["title"])] = source_id

        source_entity_type = "Publication" if metadata.get("source_type") != "internal_report" else "Report"
        source_entity_id = upsert_entity(conn, source_entity_type, metadata["title"], metadata["title"], [])

        chunks = chunk_text_with_locations(body)
        all_hits = []
        for chunk_no, chunk_info in enumerate(chunks):
            chunk = chunk_info.text
            document_id = insert_document_chunk(
                conn,
                source_id,
                chunk_no,
                chunk,
                locator_type=chunk_info.locator_type,
                locator=chunk_info.locator,
                start_char=chunk_info.start_char,
                end_char=chunk_info.end_char,
                metadata=chunk_info.metadata or {},
            )
            all_hits.extend(extract_entities(chunk, terms))
            for nh in extract_numeric_conditions(chunk, terms):
                # Attach numeric facts to the nearest process if possible, otherwise to the source entity.
                process_hits = [h for h in extract_entities(nh.evidence, terms) if h.type == "Process"]
                subject_id = source_entity_id
                if process_hits:
                    subject_id = upsert_entity(conn, "Process", process_hits[0].canonical, process_hits[0].canonical, [])
                validation_status, validation_warnings = validate_numeric_hit(nh)
                evidence_start = chunk_info.start_char + nh.start if chunk_info.start_char is not None else None
                evidence_end = chunk_info.start_char + nh.end if chunk_info.start_char is not None else None
                insert_fact(
                    conn,
                    source_id=source_id,
                    subject_id=subject_id,
                    predicate="has_numeric_condition",
                    object_id=None,
                    property_=nh.property,
                    comparator=nh.comparator,
                    numeric_value=nh.value,
                    min_value=nh.min_value,
                    max_value=nh.max_value,
                    unit=nh.unit,
                    value_text=None,
                    confidence=float(metadata.get("reliability_score", 0.55)),
                    validation_status=validation_status,
                    validation_warnings=validation_warnings,
                    document_id=document_id,
                    evidence=nh.evidence[:800],
                    evidence_locator=chunk_info.locator,
                    evidence_start=evidence_start,
                    evidence_end=evidence_end,
                    extractor_version=EXTRACTOR_VERSION,
                )

        # Graph edges: publication/report describes all extracted entities.
        seen_entities: set[tuple[str, str]] = set()
        for hit in all_hits:
            key = (hit.type, hit.canonical)
            if key in seen_entities:
                continue
            seen_entities.add(key)
            ent_id = upsert_entity(conn, hit.type, hit.canonical, hit.canonical, [])
            insert_edge(conn, source_id, source_entity_id, "describes", ent_id, float(metadata.get("reliability_score", 0.55)), hit.alias)

        # Lightweight domain relations between process/material/equipment in the same document.
        processes = [h for h in all_hits if h.type == "Process"]
        materials = [h for h in all_hits if h.type == "Material"]
        equipment = [h for h in all_hits if h.type == "Equipment"]
        for p in processes:
            p_id = upsert_entity(conn, "Process", p.canonical, p.canonical, [])
            for m in materials:
                m_id = upsert_entity(conn, "Material", m.canonical, m.canonical, [])
                insert_edge(conn, source_id, p_id, "uses_material", m_id, float(metadata.get("reliability_score", 0.55)), body[:400])
            for e in equipment:
                e_id = upsert_entity(conn, "Equipment", e.canonical, e.canonical, [])
                insert_edge(conn, source_id, p_id, "uses_equipment", e_id, float(metadata.get("reliability_score", 0.55)), body[:400])

    return title_to_source_id


def seed_experiments(conn, title_to_source_id: dict[str, int]) -> None:
    path = DATA_DIR / "experiments.csv"
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            source_id = title_to_source_id.get(row.get("source_title", ""))
            conn.execute(
                """
                INSERT INTO experiments(experiment_key, source_id, title, year, geography, material, process,
                                        conditions_json, metrics_json, result_summary, reliability_score, team)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["experiment_id"],
                    source_id,
                    row["title"],
                    int(row["year"]),
                    row["geography"],
                    row["material"],
                    row["process"],
                    row["conditions_json"],
                    row["metrics_json"],
                    row["result_summary"],
                    float(row["reliability_score"]),
                    row["team"],
                ),
            )
            exp_id = upsert_entity(conn, "Experiment", row["experiment_id"], row["experiment_id"], [row["title"]])
            process_id = upsert_entity(conn, "Process", row["process"], row["process"], [])
            insert_edge(conn, source_id, exp_id, "validated_by", process_id, float(row["reliability_score"]), row["result_summary"])
            for material in [x.strip() for x in row["material"].split(",") if x.strip()]:
                material_id = upsert_entity(conn, "Material", material, material, [])
                insert_edge(conn, source_id, exp_id, "uses_material", material_id, float(row["reliability_score"]), row["result_summary"])


def seed_experts(conn) -> None:
    experts = json.loads((DATA_DIR / "experts.json").read_text(encoding="utf-8"))
    for item in experts:
        cur = conn.execute(
            """
            INSERT INTO experts(name, organization, geography, expertise_json, contact)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                item["name"],
                item.get("organization"),
                item.get("geography"),
                json.dumps(item.get("expertise", []), ensure_ascii=False),
                item.get("contact"),
            ),
        )
        expert_entity_id = upsert_entity(conn, "Expert", item["name"], item["name"], [])
        for area in item.get("expertise", []):
            # Most expertise keys are canonical processes/materials; store as Process if known, otherwise Concept.
            area_entity_id = upsert_entity(conn, "Concept", area, area, [])
            insert_edge(conn, None, expert_entity_id, "expert_in", area_entity_id, 0.9, item.get("organization"))


def _first_document_ref(conn, source_id: int | None) -> tuple[int | None, str | None]:
    if source_id is None:
        return None, None
    row = conn.execute(
        "SELECT id, locator FROM documents WHERE source_id = ? ORDER BY chunk_no LIMIT 1",
        (source_id,),
    ).fetchone()
    if row is None:
        return None, None
    return int(row["id"]), row["locator"]


def add_manual_facts(conn, title_to_source_id: dict[str, int]) -> None:
    """A few high-value facts that the deterministic extractor would miss in MVP."""
    ro_id = upsert_entity(conn, "Process", "reverse_osmosis", "reverse_osmosis", ["обратный осмос", "reverse osmosis"])
    nf_id = upsert_entity(conn, "Process", "nanofiltration", "nanofiltration", ["нанофильтрация", "nanofiltration"])
    soft_id = upsert_entity(conn, "Process", "lime_soda_softening", "lime_soda_softening", ["известково-содовое умягчение"])
    desal_id = upsert_entity(conn, "Process", "desalination", "desalination", ["обессоливание"])
    source_id = title_to_source_id.get("Обзор методов обессоливания шахтных вод для обогатительных фабрик")
    document_id, locator = _first_document_ref(conn, source_id)
    for obj_id, evidence in [
        (soft_id, "Первая ступень для снижения Ca/Mg и риска гипсообразования."),
        (nf_id, "Нанофильтрация как первая мембранная ступень для сульфатов и жесткости."),
        (ro_id, "Обратный осмос обеспечивает TDS ниже 1000 мг/дм³ при предочистке."),
    ]:
        insert_edge(conn, source_id, desal_id, "recommended_sequence_contains", obj_id, 0.82, evidence)
        insert_fact(
            conn,
            source_id,
            desal_id,
            "recommendation",
            obj_id,
            value_text=evidence,
            confidence=0.82,
            document_id=document_id,
            evidence=evidence,
            evidence_locator=locator,
            extractor_version="manual-curated-v1",
            asserted_by="seed-curator",
        )

    cath_id = upsert_entity(conn, "Process", "catholyte_circulation", "catholyte_circulation", ["циркуляция католита"])
    source_id = title_to_source_id.get("International patent landscape on catholyte circulation in nickel electrowinning cells")
    document_id, locator = _first_document_ref(conn, source_id)
    insert_fact(
        conn,
        source_id,
        cath_id,
        "recommended_condition",
        property_="flow_velocity",
        comparator="between",
        min_value=0.15,
        max_value=0.30,
        unit="m_s",
        value_text="international consensus range",
        confidence=0.76,
        evidence="optimal catholyte flow velocity is usually reported as 0.15-0.30 m/s",
        document_id=document_id,
        evidence_locator=locator,
        extractor_version="manual-curated-v1",
        asserted_by="seed-curator",
    )
    source_id2 = title_to_source_id.get("Внутренний протокол испытаний циркуляции католита при электроэкстракции никеля")
    document_id2, locator2 = _first_document_ref(conn, source_id2)
    insert_fact(
        conn,
        source_id2,
        cath_id,
        "recommended_condition",
        property_="flow_velocity",
        comparator="between",
        min_value=0.20,
        max_value=0.35,
        unit="m_s",
        value_text="internal lab range",
        confidence=0.88,
        evidence="Оптимальная скорость циркуляции католита ... 0.20-0.35 м/с",
        document_id=document_id2,
        evidence_locator=locator2,
        extractor_version="manual-curated-v1",
        asserted_by="seed-curator",
    )


def _remove_sqlite_artifacts(path: Path) -> None:
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        candidate.unlink(missing_ok=True)


def rebuild_demo_database(db_path: Path = DB_PATH) -> Path:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = db_path.with_name(f".{db_path.name}.tmp")
    _remove_sqlite_artifacts(tmp_path)
    conn = sqlite3.connect(tmp_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = DELETE")
    try:
        create_schema(conn)
        seed_dictionary_entities(conn)
        title_map = ingest_sample_documents(conn)
        seed_experiments(conn, title_map)
        seed_experts(conn)
        add_manual_facts(conn, title_map)
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        _remove_sqlite_artifacts(tmp_path)
        raise
    else:
        conn.close()
        _remove_sqlite_artifacts(db_path)
        tmp_path.replace(db_path)
    return db_path


if __name__ == "__main__":
    path = rebuild_demo_database(DB_PATH)
    print(f"Demo DB created: {path}")
