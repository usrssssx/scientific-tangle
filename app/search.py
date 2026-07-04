from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict, deque
from datetime import datetime
from functools import lru_cache
from typing import Any

from .config import ONTOLOGY_PATH
from .db import row_to_dict, rows_to_dicts
from .embeddings import EMBEDDING_MODEL, blob_to_vector, cosine_similarity, embed_text
from .extract import canonical_unit, extract_entities, extract_numeric_conditions, load_domain_terms, load_units, normalize_key
from .models import SearchRequest
from .security import AccessContext, can_access_source, normalize_context, sql_confidentiality_clause

UNIT_CONVERSIONS: dict[tuple[str, str], float] = {
    ("g_l", "mg_l"): 1000.0,
    ("mg_l", "g_l"): 0.001,
    ("t_day", "kg_day"): 1000.0,
    ("kg_day", "t_day"): 0.001,
    ("m3_day", "m3_h"): 1.0 / 24.0,
    ("m3_h", "m3_day"): 24.0,
    ("l_s", "m3_h"): 3.6,
    ("m3_h", "l_s"): 1.0 / 3.6,
}


@lru_cache(maxsize=1)
def _search_units() -> dict[str, list[str]]:
    return load_units()


@lru_cache(maxsize=1)
def _ontology_contract() -> dict[str, Any]:
    if not ONTOLOGY_PATH.exists():
        return {}
    return json.loads(ONTOLOGY_PATH.read_text(encoding="utf-8"))


def _jsonld_context() -> dict[str, Any]:
    ontology = _ontology_contract()
    return ontology.get("jsonld_context") or {
        "@vocab": "https://example.local/rdkg/ontology#",
        "name": "http://schema.org/name",
        "confidence": "https://example.local/rdkg/ontology#confidence",
        "source": {"@id": "http://purl.org/dc/terms/source", "@type": "@id"},
    }


def _canonical_search_unit(unit: str | None) -> str | None:
    if not unit:
        return None
    return canonical_unit(unit, _search_units())


def _sql_access_clause(role: str | AccessContext, include_internal: bool = True) -> tuple[str, list[Any]]:
    return sql_confidentiality_clause(role, include_internal=include_internal, alias="s")


def parse_query(query: str) -> dict[str, Any]:
    terms = load_domain_terms()
    entity_hits = extract_entities(query, terms)
    numeric_hits = extract_numeric_conditions(query, terms)
    result: dict[str, Any] = {
        "materials": sorted({h.canonical for h in entity_hits if h.type == "Material"}),
        "processes": sorted({h.canonical for h in entity_hits if h.type == "Process"}),
        "equipment": sorted({h.canonical for h in entity_hits if h.type == "Equipment"}),
        "properties": sorted({h.canonical for h in entity_hits if h.type == "Property"}),
        "geography": sorted({h.canonical for h in entity_hits if h.type == "Geography"}),
        "numeric_conditions": [h.__dict__ for h in numeric_hits],
        "year_from": None,
        "year_to": None,
        "intent": "review",
    }
    q = query.lower().replace("ё", "е")
    if re.search(r"сравн| vs | versus |против", q):
        result["intent"] = "comparison"
    if re.search(r"эксперимент|опыт|протокол", q):
        result["intent"] = "experiments"
    if re.search(r"эксперт|команд|лаборатор", q):
        result["intent"] = "experts"
    m = re.search(r"последн(?:ие|их|ий)\s+(\d+)\s+лет", q)
    if m:
        years = int(m.group(1))
        current_year = datetime.now().year
        result["year_from"] = current_year - years + 1
        result["year_to"] = current_year
    m = re.search(r"(?:с|от)\s*(20\d{2})\s*(?:по|до|-)\s*(20\d{2})", q)
    if m:
        result["year_from"] = int(m.group(1))
        result["year_to"] = int(m.group(2))
    years_found = [int(y) for y in re.findall(r"\b(20\d{2})\b", q)]
    if len(years_found) == 1 and result["year_from"] is None:
        result["year_from"] = years_found[0]
        result["year_to"] = years_found[0]
    elif len(years_found) >= 2 and result["year_from"] is None:
        result["year_from"] = min(years_found)
        result["year_to"] = max(years_found)
    return result


def _tokenize_for_search(query: str) -> list[str]:
    stop = {
        "какие", "какой", "какая", "для", "при", "если", "исходная", "требуемый", "покажите",
        "все", "между", "последние", "где", "как", "что", "и", "в", "на", "по", "за", "the",
        "and", "or", "of", "in", "for", "with", "каковы", "считается", "описаны", "существуют",
    }
    tokens = re.findall(r"[a-zA-Zа-яА-ЯёЁ0-9]{3,}", query.lower().replace("ё", "е"))
    return [t for t in tokens if t not in stop][:32]


_FTS_NOISE_TOKENS = {
    "есть",
    "методы",
    "подходят",
    "вода",
    "воды",
    "содержит",
    "последних",
    "последние",
    "пробелы",
    "комбинации",
    "concentration",
    "total",
    "dissolved",
    "solids",
}


def _ranked_search_tokens(query: str, parsed: dict[str, Any], limit: int = 18) -> list[str]:
    alias_tokens = _aliases_for_parsed_terms(parsed)
    raw_tokens = _tokenize_for_search(query)
    candidates = alias_tokens + raw_tokens if alias_tokens else raw_tokens
    tokens: list[str] = []
    for token in candidates:
        if token.isdigit() or token in _FTS_NOISE_TOKENS:
            continue
        if token not in tokens:
            tokens.append(token)
        if len(tokens) >= limit:
            break
    return tokens or raw_tokens[:limit]


def _aliases_for_parsed_terms(parsed: dict[str, Any]) -> list[str]:
    terms = load_domain_terms()
    wanted = set(parsed.get("materials") or []) | set(parsed.get("processes") or []) | set(parsed.get("equipment") or []) | set(parsed.get("properties") or []) | set(parsed.get("geography") or [])
    aliases: list[str] = []
    category_map = ["materials", "processes", "equipment", "properties", "geography"]
    for category in category_map:
        for canonical, values in terms.get(category, {}).items():
            if canonical in wanted:
                aliases.append(canonical)
                aliases.extend(str(canonical).split("_"))
                aliases.extend(values[:8])
    tokens: list[str] = []
    for alias in aliases:
        tokens.extend(_tokenize_for_search(alias))
    return tokens


def _source_entity_names(conn: sqlite3.Connection, source_id: int) -> set[str]:
    rows = conn.execute(
        """
        SELECT DISTINCT e.normalized_name
        FROM graph_edges ge
        JOIN entities e ON e.id = ge.object_id OR e.id = ge.subject_id
        WHERE ge.source_id = ?
        """,
        (source_id,),
    ).fetchall()
    return {row["normalized_name"] for row in rows}


def _fts_match_expr(tokens: list[str]) -> str:
    # Prefix search gives decent recall for Russian endings: никел* католит*
    safe = [re.sub(r"[^a-zA-Zа-яА-ЯёЁ0-9_]", "", t) for t in tokens]
    safe = [t for t in safe if t]
    return " OR ".join(f"{t}*" for t in safe)


def _structured_group_tokens(category: str, canonical: str, limit: int = 5) -> list[str]:
    terms = load_domain_terms()
    aliases = [canonical, *str(canonical).split("_")]
    aliases.extend(terms.get(category, {}).get(canonical, [])[:8])
    tokens: list[str] = []
    for alias in aliases:
        for token in _tokenize_for_search(str(alias)):
            safe = re.sub(r"[^a-zA-Zа-яА-ЯёЁ0-9_]", "", token)
            if safe and safe not in _FTS_NOISE_TOKENS and safe not in tokens:
                tokens.append(safe)
            if len(tokens) >= limit:
                return tokens
    return tokens


def _structured_fts_match_expr(parsed: dict[str, Any]) -> str | None:
    groups: list[str] = []
    for parsed_key, category in (
        ("materials", "materials"),
        ("processes", "processes"),
        ("geography", "geography"),
    ):
        for canonical in (parsed.get(parsed_key) or [])[:6]:
            tokens = _structured_group_tokens(category, str(canonical))
            if tokens:
                groups.append("(" + " OR ".join(f"{token}*" for token in tokens) + ")")
    if len(groups) < 2:
        return None
    return " AND ".join(groups[:8])


def _embedding_query_text(query: str, parsed: dict[str, Any]) -> str:
    structured_terms: list[str] = []
    for key in ("materials", "processes", "equipment", "properties", "geography"):
        structured_terms.extend(parsed.get(key) or [])
    structured_terms.extend(_aliases_for_parsed_terms(parsed))
    return " ".join([query] + structured_terms)


def _hybrid_candidate_limit(top_k: int) -> int:
    return min(160, max(40, int(top_k) * 10))


def _document_vector_scores(
    conn: sqlite3.Connection,
    query_vector: tuple[float, ...],
    document_ids: list[int],
) -> dict[int, float]:
    if not document_ids:
        return {}
    unique_ids = list(dict.fromkeys(document_ids))
    rows = conn.execute(
        f"""
        SELECT document_id, vector_blob
        FROM document_embeddings
        WHERE model = ? AND document_id IN ({','.join('?' for _ in unique_ids)})
        """,
        [EMBEDDING_MODEL] + unique_ids,
    ).fetchall()
    scores: dict[int, float] = {}
    for row in rows:
        score = cosine_similarity(query_vector, blob_to_vector(row["vector_blob"]))
        scores[int(row["document_id"])] = max(0.0, score)
    return scores


def _supplemental_vector_candidates(
    conn: sqlite3.Connection,
    where: str,
    values: list[Any],
    existing_document_ids: set[int],
    limit: int,
) -> list[dict[str, Any]]:
    exclusion = ""
    params: list[Any] = list(values)
    if existing_document_ids:
        exclusion = f"AND d.id NOT IN ({','.join('?' for _ in existing_document_ids)})"
        params.extend(sorted(existing_document_ids))
    rows = conn.execute(
        f"""
        SELECT s.*, d.id AS document_id, d.text AS snippet, d.locator_type, d.locator,
               d.start_char, d.end_char, NULL AS rank_score, 'vector_candidate' AS retrieval_method
        FROM documents d
        JOIN sources s ON s.id = d.source_id
        WHERE {where} {exclusion}
        ORDER BY s.reliability_score DESC, s.year DESC, d.id DESC
        LIMIT ?
        """,
        params + [limit],
    ).fetchall()
    return rows_to_dicts(rows)


def search_documents(conn: sqlite3.Connection, request: SearchRequest, role: str | AccessContext, parsed: dict[str, Any]) -> list[dict[str, Any]]:
    context = normalize_context(role)
    tokens = _ranked_search_tokens(request.query, parsed)
    access_clause, params = _sql_access_clause(role, request.include_internal)
    filters = [access_clause]
    values: list[Any] = list(params)
    year_from = request.year_from or parsed.get("year_from")
    year_to = request.year_to or parsed.get("year_to")
    if year_from:
        filters.append("s.year >= ?")
        values.append(int(year_from))
    if year_to:
        filters.append("s.year <= ?")
        values.append(int(year_to))
    geos = request.geography or parsed.get("geography") or []
    if geos:
        filters.append("(s.geography IN (%s) OR s.additional_geography IN (%s))" % (",".join("?" for _ in geos), ",".join("?" for _ in geos)))
        values.extend(geos)
        values.extend(geos)
    where = " AND ".join(filters)

    rows: list[sqlite3.Row]
    if tokens:
        def run_fts(match_expr: str) -> list[sqlite3.Row]:
            return conn.execute(
                f"""
                    SELECT s.*, d.id AS document_id, d.text AS snippet, d.locator_type, d.locator,
                           d.start_char, d.end_char, bm25(documents_fts) AS rank_score,
                           'bm25' AS retrieval_method
                    FROM documents_fts
                    JOIN documents d ON d.id = documents_fts.doc_id
                    JOIN sources s ON s.id = documents_fts.source_id
                    WHERE documents_fts MATCH ? AND {where}
                    ORDER BY rank_score ASC, s.reliability_score DESC, s.year DESC
                    LIMIT ?
                    """,
                [match_expr] + values + [request.top_k * 2],
            ).fetchall()

        rows = []
        strict_match_expr = _structured_fts_match_expr(parsed)
        try:
            if strict_match_expr:
                rows = run_fts(strict_match_expr)
            if not rows:
                rows = run_fts(_fts_match_expr(tokens))
        except sqlite3.OperationalError:
            rows = []
    else:
        rows = []

    if not rows:
        like_clauses = []
        like_values: list[Any] = []
        for t in tokens[:8]:
            like_clauses.append("LOWER(d.text) LIKE ?")
            like_values.append(f"%{t}%")
        like_where = " OR ".join(like_clauses) if like_clauses else "1=1"
        rows = conn.execute(
            f"""
            SELECT s.*, d.id AS document_id, d.text AS snippet, d.locator_type, d.locator,
                   d.start_char, d.end_char, 0.0 AS rank_score, 'like' AS retrieval_method
            FROM documents d
            JOIN sources s ON s.id = d.source_id
            WHERE ({like_where}) AND {where}
            ORDER BY s.reliability_score DESC, s.year DESC
            LIMIT ?
            """,
            like_values + values + [request.top_k * 2],
        ).fetchall()

    candidate_limit = _hybrid_candidate_limit(request.top_k)
    candidates = rows_to_dicts(rows)
    existing_document_ids = {int(item["document_id"]) for item in candidates if item.get("document_id") is not None}
    if not candidates:
        candidates.extend(
            _supplemental_vector_candidates(
                conn,
                where,
                values,
                existing_document_ids,
                candidate_limit - len(candidates),
            )
        )

    docs = [doc for doc in candidates if can_access_source(doc, context)]
    query_vector = embed_text(_embedding_query_text(request.query, parsed))
    vector_scores = _document_vector_scores(
        conn,
        query_vector,
        [int(doc["document_id"]) for doc in docs if doc.get("document_id") is not None],
    )
    # Score by parsed entities too.
    materials = set(request.material or parsed.get("materials") or [])
    processes = set(request.process or parsed.get("processes") or [])
    props = set(parsed.get("properties") or [])
    term_alias_tokens = set(_aliases_for_parsed_terms(parsed))
    source_entity_cache: dict[int, set[str]] = {}
    for item in docs:
        text = normalize_key((item.get("title") or "") + " " + (item.get("snippet") or ""))
        score = float(item.get("reliability_score") or 0.5)
        rank_score = item.get("rank_score")
        bm25_score = 0.0
        if rank_score is not None:
            try:
                bm25_score = 1.0 / (1.0 + abs(float(rank_score)))
            except (TypeError, ValueError):
                bm25_score = 0.0
        vector_score = vector_scores.get(int(item.get("document_id") or 0), 0.0)
        score += bm25_score * 0.25 + vector_score * 0.55
        item["bm25_score"] = round(bm25_score, 4)
        item["vector_score"] = round(vector_score, 4)
        source_id = int(item["id"])
        if source_id not in source_entity_cache:
            source_entity_cache[source_id] = _source_entity_names(conn, source_id)
        source_entities = source_entity_cache[source_id]
        item["matched_entities"] = sorted(source_entities & (materials | processes | props))
        for term in materials | processes | props:
            if term in source_entities:
                score += 0.45
            elif term.replace("_", " ") in text or term in text:
                score += 0.25
        for tok in term_alias_tokens:
            if tok in text:
                score += 0.03
        item["score"] = round(score, 3)
        if item.get("snippet") and len(item["snippet"]) > 700:
            item["snippet"] = item["snippet"][:700] + "..."
    # De-dupe by source id, keep best score.
    by_id: dict[int, dict[str, Any]] = {}
    for item in docs:
        sid = item["id"]
        if sid not in by_id or item["score"] > by_id[sid]["score"]:
            by_id[sid] = item
    ordered = sorted(by_id.values(), key=lambda x: (x.get("score", 0), x.get("year") or 0), reverse=True)
    if ordered and ordered[0].get("score", 0) >= 1.5:
        threshold = max(1.0, float(ordered[0].get("score", 0)) * 0.30)
        ordered = [d for d in ordered if d.get("score", 0) >= threshold or d.get("matched_entities")]
    return ordered[: request.top_k]


def _convert_numeric(value: float | None, from_unit: str | None, to_unit: str | None) -> float | None:
    if value is None:
        return None
    from_unit = _canonical_search_unit(from_unit)
    to_unit = _canonical_search_unit(to_unit)
    if not from_unit or not to_unit or from_unit == to_unit:
        return float(value)
    factor = UNIT_CONVERSIONS.get((from_unit, to_unit))
    if factor is None:
        return None
    return float(value) * factor


def _condition_interval(item: dict[str, Any], value_key: str = "value") -> tuple[float | None, float | None]:
    comparator = item.get("comparator") or "="
    value = item.get(value_key)
    min_value = item.get("min_value")
    max_value = item.get("max_value")
    if comparator == "between":
        return (float(min_value) if min_value is not None else None, float(max_value) if max_value is not None else None)
    if value is None and item.get("numeric_value") is not None:
        value = item.get("numeric_value")
    if value is None:
        return (float(min_value) if min_value is not None else None, float(max_value) if max_value is not None else None)
    value = float(value)
    if comparator in {"<=", "<"}:
        return (None, value)
    if comparator in {">=", ">"}:
        return (value, None)
    return (value, value)


def _condition_overlap(filter_cond: dict[str, Any], fact: dict[str, Any]) -> bool:
    if filter_cond.get("property") and fact.get("property") and filter_cond["property"] != fact["property"]:
        return False
    filter_unit = _canonical_search_unit(filter_cond.get("unit"))
    fact_unit = _canonical_search_unit(fact.get("unit"))
    if filter_unit:
        filter_cond = dict(filter_cond)
        filter_cond["unit"] = filter_unit
    if fact_unit:
        fact = dict(fact)
        fact["unit"] = fact_unit
    if filter_unit and fact_unit and filter_unit != fact_unit:
        converted_fact = dict(fact)
        for key in ("numeric_value", "min_value", "max_value"):
            converted = _convert_numeric(fact.get(key), fact_unit, filter_unit)
            if fact.get(key) is not None and converted is None:
                return False
            converted_fact[key] = converted
        converted_fact["unit"] = filter_unit
        fact = converted_fact
    qmin, qmax = _condition_interval(filter_cond, value_key="value")
    fmin, fmax = _condition_interval(fact, value_key="numeric_value")
    if qmin is None and qmax is None:
        return True
    if fmin is None and fmax is None:
        return False
    lower = max(v for v in [qmin, fmin] if v is not None) if qmin is not None or fmin is not None else None
    upper = min(v for v in [qmax, fmax] if v is not None) if qmax is not None or fmax is not None else None
    if lower is not None and upper is not None:
        return lower <= upper
    return True


def search_facts(conn: sqlite3.Connection, request: SearchRequest, parsed: dict[str, Any], source_ids: list[int], role: str | AccessContext) -> list[dict[str, Any]]:
    context = normalize_context(role)
    values: list[Any] = []
    filters: list[str] = []
    access_clause, access_values = _sql_access_clause(context, request.include_internal)
    filters.append(f"(s.id IS NULL OR {access_clause})")
    values.extend(access_values)
    if source_ids:
        filters.append("f.source_id IN (%s)" % ",".join("?" for _ in source_ids))
        values.extend(source_ids)
    properties = set(parsed.get("properties") or [])
    for nh in parsed.get("numeric_conditions") or []:
        if nh.get("property"):
            properties.add(nh["property"])
    for nf in request.numeric_filters:
        if nf.property:
            properties.add(nf.property)
    if properties:
        filters.append("(f.property IN (%s) OR f.predicate IN ('recommendation', 'recommended_condition'))" % ",".join("?" for _ in properties))
        values.extend(list(properties))
    if request.min_confidence:
        filters.append("f.confidence >= ?")
        values.append(request.min_confidence)
    where = "WHERE " + " AND ".join(filters) if filters else ""
    rows = conn.execute(
        f"""
        SELECT f.*, s.title AS source_title, s.year AS source_year, s.geography AS source_geography,
               s.confidentiality, s.metadata_json,
               es.name AS subject_name, es.type AS subject_type, eo.name AS object_name, eo.type AS object_type
        FROM facts f
        LEFT JOIN sources s ON s.id = f.source_id
        LEFT JOIN entities es ON es.id = f.subject_id
        LEFT JOIN entities eo ON eo.id = f.object_id
        {where}
        ORDER BY f.confidence DESC, s.year DESC
        LIMIT ?
        """,
        values + [max(30, request.top_k * 4)],
    ).fetchall()
    facts = [fact for fact in rows_to_dicts(rows) if fact.get("source_id") is None or can_access_source(fact, context)]
    # Keep facts from sources that actually mention the parsed core entities.
    core_terms = set(parsed.get("materials") or []) | set(parsed.get("processes") or [])
    if core_terms and source_ids:
        source_entity_cache = {sid: _source_entity_names(conn, sid) for sid in source_ids}
        filtered_facts = []
        for fact in facts:
            sid = fact.get("source_id")
            source_entities = source_entity_cache.get(int(sid), set()) if sid else set()
            subject = normalize_key(str(fact.get("subject_name") or ""))
            obj = normalize_key(str(fact.get("object_name") or ""))
            if source_entities & core_terms or subject in core_terms or obj in core_terms:
                filtered_facts.append(fact)
        if filtered_facts:
            facts = filtered_facts
    numeric_conditions = list(parsed.get("numeric_conditions") or []) + [nf.model_dump() for nf in request.numeric_filters]
    if numeric_conditions:
        boosted = []
        for fact in facts:
            fact["numeric_match"] = any(_condition_overlap(cond, fact) for cond in numeric_conditions)
            boosted.append(fact)
        if request.strict_numeric_filters:
            boosted = [fact for fact in boosted if fact.get("numeric_match")]
        facts = sorted(boosted, key=lambda f: (f.get("numeric_match", False), f.get("confidence") or 0), reverse=True)
    for fact in facts:
        if fact.get("evidence") and len(fact["evidence"]) > 450:
            fact["evidence"] = fact["evidence"][:450] + "..."
    return facts[: max(20, request.top_k * 3)]


def _fact_value(fact: dict[str, Any]) -> dict[str, Any]:
    return {
        "property": fact.get("property"),
        "comparator": fact.get("comparator"),
        "numeric_value": fact.get("numeric_value"),
        "min_value": fact.get("min_value"),
        "max_value": fact.get("max_value"),
        "unit": fact.get("unit"),
        "value_text": fact.get("value_text"),
    }


def build_evidence_pack(docs: list[dict[str, Any]], facts: list[dict[str, Any]], limit: int = 30) -> dict[str, Any]:
    snippets = []
    for source in docs[:limit]:
        snippets.append(
            {
                "source_id": source.get("id"),
                "document_id": source.get("document_id"),
                "title": source.get("title"),
                "year": source.get("year"),
                "source_confidentiality": source.get("confidentiality"),
                "locator": source.get("locator"),
                "span": [source.get("start_char"), source.get("end_char")],
                "snippet": source.get("snippet"),
                "confidence": source.get("reliability_score"),
            }
        )
    fact_items = []
    for fact in facts[:limit]:
        fact_items.append(
            {
                "fact_id": fact.get("id"),
                "source_id": fact.get("source_id"),
                "document_id": fact.get("document_id"),
                "source_title": fact.get("source_title"),
                "source_year": fact.get("source_year"),
                "source_confidentiality": fact.get("confidentiality"),
                "locator": fact.get("evidence_locator"),
                "span": [fact.get("evidence_start"), fact.get("evidence_end")],
                "predicate": fact.get("predicate"),
                "subject": fact.get("subject_name"),
                "object": fact.get("object_name"),
                "value": _fact_value(fact),
                "evidence": fact.get("evidence"),
                "confidence": fact.get("confidence"),
                "extraction_confidence": fact.get("extraction_confidence"),
                "validation_status": fact.get("validation_status"),
                "validation_warnings": fact.get("validation_warnings") or [],
                "extractor_version": fact.get("extractor_version"),
            }
        )
    return {"source_snippets": snippets, "facts": fact_items}


def search_experiments(conn: sqlite3.Connection, request: SearchRequest, parsed: dict[str, Any]) -> list[dict[str, Any]]:
    materials = set(request.material or parsed.get("materials") or [])
    processes = set(request.process or parsed.get("processes") or [])
    geos = set(request.geography or parsed.get("geography") or [])
    year_from = request.year_from or parsed.get("year_from")
    year_to = request.year_to or parsed.get("year_to")
    rows = conn.execute("SELECT * FROM experiments ORDER BY reliability_score DESC, year DESC").fetchall()
    experiments = rows_to_dicts(rows)
    filtered: list[dict[str, Any]] = []
    for exp in experiments:
        text = normalize_key(" ".join(str(exp.get(k) or "") for k in ["title", "material", "process", "result_summary", "team"]))
        if materials and not any(m in text for m in materials):
            continue
        if processes and not any(p in text for p in processes):
            # Allow process mismatch when the experiment strongly overlaps by material set, e.g.
            # flash_smelting experiment is still relevant for matte-slag partitioning of Au/Ag/PGM.
            material_overlap_count = sum(1 for m in materials if m in text)
            if not any(p.replace("_", " ") in text for p in processes) and material_overlap_count < 2:
                continue
        if geos and exp.get("geography") not in geos:
            continue
        if year_from and (exp.get("year") or 0) < int(year_from):
            continue
        if year_to and (exp.get("year") or 9999) > int(year_to):
            continue
        filtered.append(exp)
    if not filtered and (materials or processes):
        # Return near-misses to help gap detection.
        for exp in experiments:
            text = normalize_key(" ".join(str(exp.get(k) or "") for k in ["title", "material", "process", "result_summary", "team"]))
            if any(term in text for term in materials | processes):
                filtered.append(exp)
    return filtered[: request.top_k]


def search_experts(conn: sqlite3.Connection, request: SearchRequest, parsed: dict[str, Any]) -> list[dict[str, Any]]:
    topics = set(parsed.get("materials") or []) | set(parsed.get("processes") or []) | set(parsed.get("equipment") or []) | set(parsed.get("properties") or [])
    rows = conn.execute("SELECT * FROM experts ORDER BY name").fetchall()
    experts = rows_to_dicts(rows)
    scored: list[dict[str, Any]] = []
    for expert in experts:
        expertise = set(expert.get("expertise") or [])
        overlap = topics & expertise
        # Also normalize underscores for partial matches.
        if not overlap:
            text = normalize_key(" ".join(expertise))
            overlap = {t for t in topics if t in text or t.replace("_", " ") in text}
        if overlap or not topics:
            expert["matched_topics"] = sorted(overlap)
            expert["score"] = len(overlap)
            scored.append(expert)
    return sorted(scored, key=lambda e: e.get("score", 0), reverse=True)[: request.top_k]


def detect_gaps(parsed: dict[str, Any], experiments: list[dict[str, Any]], docs: list[dict[str, Any]]) -> list[str]:
    gaps: list[str] = []
    materials = set(parsed.get("materials") or [])
    processes = set(parsed.get("processes") or [])
    if not docs:
        gaps.append("В базе нет документов, уверенно соответствующих запросу. Нужно загрузить корпус или расширить словари синонимов.")
    if not experiments and (materials or processes):
        gaps.append("По найденной комбинации материалов/процессов нет связанных экспериментов; выводы будут основаны только на документах.")
    if {"cold_climate_operation", "heap_leaching"}.issubset(processes) and "nickel" in materials:
        exact = [e for e in experiments if "heap" in normalize_key(e.get("process") or "") and "nickel" in normalize_key(e.get("material") or "")]
        if not exact:
            gaps.append("Пробел: не найдено подтвержденных экспериментов для комбинации холодный климат + кучное выщелачивание + никелевая руда.")
    if parsed.get("numeric_conditions") and not any(f.get("numeric_match") for f in []):
        # search_facts adds numeric_match later; this generic note is intentionally conservative.
        pass
    return gaps


def detect_contradictions(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for fact in facts:
        if fact.get("property") and (fact.get("min_value") is not None or fact.get("numeric_value") is not None):
            groups[(fact.get("subject_name"), fact.get("property"), fact.get("unit"))].append(fact)
    result: list[dict[str, Any]] = []
    for key, items in groups.items():
        if len(items) < 2:
            continue
        intervals = []
        for item in items:
            if item.get("numeric_value") is not None:
                lo = hi = float(item["numeric_value"])
            else:
                lo = float(item.get("min_value") or 0)
                hi = float(item.get("max_value") or lo)
            intervals.append((lo, hi, item))
        min_hi = min(i[1] for i in intervals)
        max_lo = max(i[0] for i in intervals)
        if max_lo > min_hi:
            severity = "contradiction"
            comment = "Диапазоны не пересекаются. Нужна экспертная верификация."
        else:
            unique_ranges = {(round(i[0], 6), round(i[1], 6)) for i in intervals}
            if len(unique_ranges) == 1:
                continue
            severity = "range_divergence"
            comment = "Диапазоны частично различаются, но пересекаются; это зона уточнения, а не жесткое противоречие."
        result.append({
            "subject": key[0],
            "property": key[1],
            "unit": key[2],
            "severity": severity,
            "comment": comment,
            "sources": [
                {
                    "source_title": i[2].get("source_title"),
                    "range": [i[0], i[1]],
                    "confidence": i[2].get("confidence"),
                    "evidence": i[2].get("evidence"),
                }
                for i in intervals
            ],
        })
    return result[:10]


def run_search(conn: sqlite3.Connection, request: SearchRequest, role: str | AccessContext = "researcher") -> dict[str, Any]:
    context = normalize_context(role)
    parsed = parse_query(request.query)
    docs = search_documents(conn, request, context, parsed)
    source_ids = [int(d["id"]) for d in docs]
    facts = search_facts(conn, request, parsed, source_ids, context)
    experiments = search_experiments(conn, request, parsed)
    experts = search_experts(conn, request, parsed)
    contradictions = detect_contradictions(facts)
    gaps = detect_gaps(parsed, experiments, docs)
    if parsed.get("numeric_conditions") and facts and not any(f.get("numeric_match") for f in facts if f.get("property")):
        gaps.append("Числовые условия распознаны, но в фактах нет точного совпадения по свойству/единице. Проверьте нормализацию единиц и словарь параметров.")
    evidence_pack = build_evidence_pack(docs, facts)
    answer_mode = request.answer_mode
    if answer_mode == "auto":
        if gaps or "gap" in normalize_key(request.query) or "пробел" in normalize_key(request.query):
            answer_mode = "gap_analysis"
        elif parsed.get("intent") == "comparison":
            answer_mode = "comparison"
        elif parsed.get("intent") == "experiments":
            answer_mode = "protocol"
        else:
            answer_mode = "review"
    return {
        "query": request.query,
        "answer_mode": answer_mode,
        "parsed_query": parsed,
        "sources": docs,
        "facts": facts,
        "evidence_pack": evidence_pack,
        "experiments": experiments,
        "experts": experts,
        "gaps": gaps,
        "contradictions": contradictions,
    }


def get_graph(conn: sqlite3.Connection, entity_query: str, role: str | AccessContext = "researcher", depth: int = 2, limit: int = 60) -> dict[str, Any]:
    context = normalize_context(role)
    q = normalize_key(entity_query)
    start_rows = conn.execute(
        """
        SELECT * FROM entities
        WHERE normalized_name LIKE ? OR LOWER(name) LIKE ?
        ORDER BY CASE WHEN normalized_name = ? THEN 0 ELSE 1 END, type, name
        LIMIT 5
        """,
        (f"%{q}%", f"%{q}%", q),
    ).fetchall()
    if not start_rows:
        return {"nodes": [], "edges": []}
    start_ids = [int(row["id"]) for row in start_rows]
    visited = set(start_ids)
    nodes: dict[int, dict[str, Any]] = {int(row["id"]): row_to_dict(row) for row in start_rows}
    edges: list[dict[str, Any]] = []
    queue = deque([(sid, 0) for sid in start_ids])
    while queue and len(nodes) < limit:
        current, dist = queue.popleft()
        if dist >= depth:
            continue
        rows = conn.execute(
            """
            SELECT ge.*, s.confidentiality, s.title AS source_title,
                   s.metadata_json,
                   a.name AS subject_name, a.type AS subject_type,
                   b.name AS object_name, b.type AS object_type
            FROM graph_edges ge
            LEFT JOIN sources s ON s.id = ge.source_id
            JOIN entities a ON a.id = ge.subject_id
            JOIN entities b ON b.id = ge.object_id
            WHERE ge.subject_id = ? OR ge.object_id = ?
            LIMIT 100
            """,
            (current, current),
        ).fetchall()
        for row in rows:
            item = row_to_dict(row)
            if item.get("source_id") is not None and not can_access_source(item, context):
                continue
            edges.append(item)
            for nid in [int(item["subject_id"]), int(item["object_id"])] :
                if nid not in nodes:
                    nrow = conn.execute("SELECT * FROM entities WHERE id = ?", (nid,)).fetchone()
                    if nrow:
                        nodes[nid] = row_to_dict(nrow)
                if nid not in visited and len(nodes) < limit:
                    visited.add(nid)
                    queue.append((nid, dist + 1))
    return {"nodes": list(nodes.values()), "edges": edges[: limit * 2]}


def dashboard_metrics(conn: sqlite3.Connection, role: str | AccessContext = "manager") -> dict[str, Any]:
    context = normalize_context(role)
    access_clause, access_values = _sql_access_clause(context, include_internal=True)
    source_rows = rows_to_dicts(
        conn.execute(
            f"SELECT id, source_type, confidentiality, metadata_json, year, updated_at FROM sources s WHERE {access_clause}",
            access_values,
        ).fetchall()
    )
    accessible_sources = [source for source in source_rows if can_access_source(source, context)]
    counts: dict[str, int] = defaultdict(int)
    for source in accessible_sources:
        counts[source.get("source_type") or "unknown"] += 1
    source_counts = [{"source_type": key, "count": counts[key]} for key in sorted(counts)]
    source_ids = [int(source["id"]) for source in accessible_sources]
    current_year = datetime.now().year
    manager_summary = {
        "sources": len(source_ids),
        "facts": 0,
        "verified_facts": 0,
        "candidate_facts": 0,
        "contradicted_facts": 0,
        "open_disputes": 0,
        "overdue_disputes": 0,
        "stale_sources": 0,
    }
    fact_status_counts: list[dict[str, Any]] = []
    validation_status_counts: list[dict[str, Any]] = []
    freshness_by_year: list[dict[str, Any]] = []
    stale_sources: list[dict[str, Any]] = []
    fact_coverage_by_property: list[dict[str, Any]] = []
    disputes_by_severity: list[dict[str, Any]] = []
    overdue_disputes: list[dict[str, Any]] = []
    team_activity: list[dict[str, Any]] = []
    audit_activity: list[dict[str, Any]] = []
    if source_ids:
        placeholders = ",".join("?" for _ in source_ids)
        entity_counts = rows_to_dicts(
            conn.execute(
                f"""
                SELECT e.type, COUNT(DISTINCT e.id) AS count
                FROM entities e
                JOIN graph_edges ge ON ge.subject_id = e.id OR ge.object_id = e.id
                WHERE ge.source_id IN ({placeholders})
                GROUP BY e.type
                ORDER BY count DESC
                """,
                source_ids,
            ).fetchall()
        )
        fact_status_counts = rows_to_dicts(
            conn.execute(
                f"""
                SELECT COALESCE(f.status, 'candidate') AS status, COUNT(*) AS count
                FROM facts f
                WHERE f.source_id IN ({placeholders})
                GROUP BY COALESCE(f.status, 'candidate')
                ORDER BY count DESC
                """,
                source_ids,
            ).fetchall()
        )
        validation_status_counts = rows_to_dicts(
            conn.execute(
                f"""
                SELECT COALESCE(f.validation_status, 'valid') AS validation_status, COUNT(*) AS count
                FROM facts f
                WHERE f.source_id IN ({placeholders})
                GROUP BY COALESCE(f.validation_status, 'valid')
                ORDER BY count DESC
                """,
                source_ids,
            ).fetchall()
        )
        fact_coverage_by_property = rows_to_dicts(
            conn.execute(
                f"""
                SELECT COALESCE(f.property, f.predicate, 'unknown') AS topic, COUNT(*) AS facts,
                       COUNT(DISTINCT f.source_id) AS sources,
                       SUM(CASE WHEN f.status = 'verified' THEN 1 ELSE 0 END) AS verified_facts,
                       SUM(CASE WHEN f.validation_status NOT IN ('valid', '') THEN 1 ELSE 0 END) AS flagged_facts
                FROM facts f
                WHERE f.source_id IN ({placeholders})
                GROUP BY COALESCE(f.property, f.predicate, 'unknown')
                ORDER BY facts DESC
                LIMIT 25
                """,
                source_ids,
            ).fetchall()
        )
        freshness_by_year = rows_to_dicts(
            conn.execute(
                f"""
                SELECT COALESCE(CAST(s.year AS TEXT), 'unknown') AS year_bucket, COUNT(*) AS count
                FROM sources s
                WHERE s.id IN ({placeholders})
                GROUP BY COALESCE(CAST(s.year AS TEXT), 'unknown')
                ORDER BY CASE WHEN s.year IS NULL THEN 0 ELSE s.year END DESC
                LIMIT 20
                """,
                source_ids,
            ).fetchall()
        )
        stale_sources = rows_to_dicts(
            conn.execute(
                f"""
                SELECT s.id, s.title, s.source_type, s.year, s.confidentiality
                FROM sources s
                WHERE s.id IN ({placeholders}) AND (s.year IS NULL OR s.year < ?)
                ORDER BY CASE WHEN s.year IS NULL THEN 0 ELSE 1 END ASC, s.year ASC, s.id DESC
                LIMIT 25
                """,
                source_ids + [current_year - 5],
            ).fetchall()
        )
        stale_source_count = int(
            conn.execute(
                f"""
                SELECT COUNT(*) AS count
                FROM sources s
                WHERE s.id IN ({placeholders}) AND (s.year IS NULL OR s.year < ?)
                """,
                source_ids + [current_year - 5],
            ).fetchone()["count"]
        )
        disputes_by_severity = rows_to_dicts(
            conn.execute(
                f"""
                SELECT fd.severity, fd.status, COUNT(*) AS count
                FROM fact_disputes fd
                JOIN facts f ON f.id = fd.fact_id
                WHERE f.source_id IN ({placeholders})
                GROUP BY fd.severity, fd.status
                ORDER BY count DESC
                """,
                source_ids,
            ).fetchall()
        )
        overdue_disputes = rows_to_dicts(
            conn.execute(
                f"""
                SELECT fd.id, fd.fact_id, fd.severity, fd.status, fd.assignee, fd.due_at, fd.reason,
                       s.title AS source_title, f.property, f.predicate
                FROM fact_disputes fd
                JOIN facts f ON f.id = fd.fact_id
                LEFT JOIN sources s ON s.id = f.source_id
                WHERE f.source_id IN ({placeholders})
                  AND fd.status IN ('open', 'escalated')
                  AND fd.due_at IS NOT NULL
                  AND fd.due_at < CURRENT_TIMESTAMP
                ORDER BY fd.due_at ASC, fd.id DESC
                LIMIT 25
                """,
                source_ids,
            ).fetchall()
        )
        overdue_dispute_count = int(
            conn.execute(
                f"""
                SELECT COUNT(*) AS count
                FROM fact_disputes fd
                JOIN facts f ON f.id = fd.fact_id
                WHERE f.source_id IN ({placeholders})
                  AND fd.status IN ('open', 'escalated')
                  AND fd.due_at IS NOT NULL
                  AND fd.due_at < CURRENT_TIMESTAMP
                """,
                source_ids,
            ).fetchone()["count"]
        )
        team_activity = rows_to_dicts(
            conn.execute(
                f"""
                SELECT COALESCE(fr.reviewer, 'unknown') AS reviewer, fr.action, COUNT(*) AS count,
                       MAX(fr.created_at) AS latest_at
                FROM fact_reviews fr
                JOIN facts f ON f.id = fr.fact_id
                WHERE f.source_id IN ({placeholders})
                GROUP BY COALESCE(fr.reviewer, 'unknown'), fr.action
                ORDER BY latest_at DESC, count DESC
                LIMIT 25
                """,
                source_ids,
            ).fetchall()
        )
        audit_activity = rows_to_dicts(
            conn.execute(
                """
                SELECT action, role, COUNT(*) AS count, MAX(created_at) AS latest_at
                FROM audit_log
                WHERE action LIKE 'curation_%'
                   OR action LIKE 'fact_%'
                   OR action LIKE 'export_%'
                   OR action LIKE 'ingest_%'
                GROUP BY action, role
                ORDER BY latest_at DESC, count DESC
                LIMIT 25
                """
            ).fetchall()
        )
        total_facts = sum(int(item["count"]) for item in fact_status_counts)
        manager_summary.update(
            {
                "facts": total_facts,
                "verified_facts": sum(int(item["count"]) for item in fact_status_counts if item["status"] == "verified"),
                "candidate_facts": sum(int(item["count"]) for item in fact_status_counts if item["status"] == "candidate"),
                "contradicted_facts": sum(int(item["count"]) for item in fact_status_counts if item["status"] == "contradicted"),
                "open_disputes": sum(
                    int(item["count"]) for item in disputes_by_severity if item.get("status") in {"open", "escalated"}
                ),
                "overdue_disputes": overdue_dispute_count,
                "stale_sources": stale_source_count,
            }
        )
    else:
        entity_counts = []
    exp_by_domain = rows_to_dicts(conn.execute("SELECT process, COUNT(*) AS count FROM experiments GROUP BY process ORDER BY count DESC").fetchall())
    if source_ids:
        placeholders = ",".join("?" for _ in source_ids)
        risky_topics = rows_to_dicts(
            conn.execute(
                f"""
                SELECT e.name, e.type, COUNT(ge.id) AS edges
                FROM entities e
                JOIN graph_edges ge ON ge.subject_id = e.id OR ge.object_id = e.id
                WHERE e.type IN ('Process', 'Material') AND ge.source_id IN ({placeholders})
                GROUP BY e.id
                HAVING edges <= 1
                ORDER BY edges ASC, e.name
                LIMIT 20
                """,
                source_ids,
            ).fetchall()
        )
    else:
        risky_topics = []
    return {
        "manager_summary": manager_summary,
        "sources_by_type": source_counts,
        "source_freshness_by_year": freshness_by_year,
        "stale_sources": stale_sources,
        "entities_by_type": entity_counts,
        "fact_status_counts": fact_status_counts,
        "validation_status_counts": validation_status_counts,
        "fact_coverage_by_property": fact_coverage_by_property,
        "experiments_by_process": exp_by_domain,
        "risk_zones_low_connectivity": risky_topics,
        "disputes_by_severity": disputes_by_severity,
        "overdue_disputes": overdue_disputes,
        "team_activity": team_activity,
        "audit_activity": audit_activity,
    }


def _export_edge_rows(conn: sqlite3.Connection, source_ids: list[int] | None, role: str | AccessContext, limit: int) -> list[dict[str, Any]]:
    context = normalize_context(role)
    filters = []
    values: list[Any] = []
    if source_ids:
        filters.append("ge.source_id IN (%s)" % ",".join("?" for _ in source_ids))
        values.extend(source_ids)
    access_clause, access_values = _sql_access_clause(role, include_internal=True)
    filters.append(f"(ge.source_id IS NULL OR {access_clause})")
    values.extend(access_values)
    where = "WHERE " + " AND ".join(filters) if filters else ""
    rows = conn.execute(
        f"""
        SELECT ge.*, s.confidentiality, s.metadata_json, a.name AS subject_name, a.type AS subject_type, b.name AS object_name, b.type AS object_type
        FROM graph_edges ge
        LEFT JOIN sources s ON s.id = ge.source_id
        JOIN entities a ON a.id = ge.subject_id
        JOIN entities b ON b.id = ge.object_id
        {where}
        ORDER BY ge.id
        LIMIT ?
        """,
        values + [limit],
    ).fetchall()
    result = []
    for row in rows_to_dicts(rows):
        if row.get("source_id") is not None and not can_access_source(row, context):
            continue
        result.append(row)
    return result


def export_jsonld(conn: sqlite3.Connection, source_ids: list[int] | None = None, role: str | AccessContext = "researcher", limit: int = 200) -> dict[str, Any]:
    graph = []
    for row in _export_edge_rows(conn, source_ids, role, limit):
        relation_id = f"urn:rdkg:relation:{row['id']}"
        subject = {
            "@id": f"urn:rdkg:entity:{row['subject_id']}",
            "@type": row["subject_type"],
            "name": row["subject_name"],
        }
        object_node = {
            "@id": f"urn:rdkg:entity:{row['object_id']}",
            "@type": row["object_type"],
            "name": row["object_name"],
            "confidence": row.get("confidence"),
            "source": f"urn:rdkg:source:{row['source_id']}" if row.get("source_id") else None,
            "source_id": row.get("source_id"),
        }
        legacy_object = dict(object_node)
        legacy_object["source"] = row.get("source_id")
        graph.append({
            "@id": relation_id,
            "@type": "RelationAssertion",
            "subject": subject,
            "predicate": row["predicate"],
            "object": object_node,
            "confidence": row.get("confidence"),
            "source": f"urn:rdkg:source:{row['source_id']}" if row.get("source_id") else None,
            "source_id": row.get("source_id"),
            "source_confidentiality": row.get("confidentiality"),
            "evidence": row.get("evidence"),
            row["predicate"]: {
                key: value for key, value in legacy_object.items() if value is not None
            },
        })
    return {"@context": _jsonld_context(), "@graph": graph}


def _turtle_literal(value: Any) -> str:
    text = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    return f'"{text}"'


def _turtle_iri(value: str) -> str:
    return f"<{value}>"


def export_rdf_turtle(conn: sqlite3.Connection, source_ids: list[int] | None = None, role: str | AccessContext = "researcher", limit: int = 200) -> str:
    lines = [
        "@prefix rdkg: <https://example.local/rdkg/ontology#> .",
        "@prefix dct: <http://purl.org/dc/terms/> .",
        "@prefix schema: <http://schema.org/> .",
        "",
    ]
    for row in _export_edge_rows(conn, source_ids, role, limit):
        relation = _turtle_iri(f"urn:rdkg:relation:{row['id']}")
        subject = _turtle_iri(f"urn:rdkg:entity:{row['subject_id']}")
        obj = _turtle_iri(f"urn:rdkg:entity:{row['object_id']}")
        predicate = f"rdkg:{row['predicate']}"
        lines.extend(
            [
                f"{subject} a rdkg:{row['subject_type']} ;",
                f"  schema:name {_turtle_literal(row['subject_name'])} .",
                f"{obj} a rdkg:{row['object_type']} ;",
                f"  schema:name {_turtle_literal(row['object_name'])} .",
                f"{subject} {predicate} {obj} .",
                f"{relation} a rdkg:RelationAssertion ;",
                f"  rdkg:subject {subject} ;",
                f"  rdkg:predicate {_turtle_literal(row['predicate'])} ;",
                f"  rdkg:object {obj} ;",
            ]
        )
        if row.get("source_id"):
            source_iri = _turtle_iri(f"urn:rdkg:source:{row['source_id']}")
            lines.append(f"  dct:source {source_iri} ;")
        if row.get("confidentiality"):
            lines.append(f"  rdkg:sourceConfidentiality {_turtle_literal(row['confidentiality'])} ;")
        if row.get("confidence") is not None:
            lines.append(f"  rdkg:confidence {_turtle_literal(row['confidence'])} ;")
        if row.get("evidence"):
            lines.append(f"  rdkg:evidence {_turtle_literal(row['evidence'])} ;")
        if lines[-1].endswith(";"):
            lines[-1] = lines[-1][:-1] + "."
        lines.append("")
    return "\n".join(lines)
