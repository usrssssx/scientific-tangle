from app.db import connect, create_schema, insert_document_chunk, insert_edge, insert_source, upsert_entity
from app.models import NumericFilter, SearchRequest
from app.search import _condition_overlap, export_jsonld, export_rdf_turtle, get_graph, run_search
from app.seed_data import rebuild_demo_database


def build_test_db(tmp_path):
    db_path = tmp_path / "rd_knowledge_test.sqlite"
    rebuild_demo_database(db_path)
    return db_path


def test_desalination_query_finds_numeric_tds(tmp_path):
    db_path = build_test_db(tmp_path)
    q = "Какие методы обессоливания подходят, если сульфаты 200-300 мг/л и сухой остаток ≤1000 мг/дм³?"
    with connect(db_path) as conn:
        result = run_search(conn, SearchRequest(query=q), role="researcher")
    assert result["sources"]
    assert any(f.get("property") == "tds" for f in result["facts"])
    assert result["evidence_pack"]["facts"]
    first_fact = result["evidence_pack"]["facts"][0]
    assert first_fact["fact_id"] is not None
    assert first_fact["document_id"] is not None
    assert first_fact["extractor_version"]
    assert "validation_status" in first_fact


def test_catholyte_query_finds_foreign_source(tmp_path):
    db_path = build_test_db(tmp_path)
    q = "Какие решения циркуляции католита при электроэкстракции никеля описаны в мировой практике?"
    with connect(db_path) as conn:
        result = run_search(conn, SearchRequest(query=q), role="researcher")
    titles = [s["title"] for s in result["sources"]]
    assert any("patent landscape" in t for t in titles)


def test_search_uses_hybrid_document_embeddings(tmp_path):
    db_path = tmp_path / "hybrid.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)
        source_id = insert_source(
            conn,
            {"title": "Reverse osmosis pilot", "confidentiality": "internal", "source_type": "test", "reliability_score": 0.8},
        )
        document_id = insert_document_chunk(
            conn,
            source_id,
            0,
            "reverse osmosis membrane reduced total dissolved solids in mine water",
            locator="page 1",
        )
        embedding_count = conn.execute("SELECT COUNT(*) FROM document_embeddings WHERE document_id = ?", (document_id,)).fetchone()[0]
        result = run_search(conn, SearchRequest(query="reverse osmosis membrane tds", top_k=3), role="researcher")

    assert embedding_count == 1
    assert result["sources"]
    first = result["sources"][0]
    assert first["title"] == "Reverse osmosis pilot"
    assert first["retrieval_method"] in {"bm25", "like", "vector_candidate"}
    assert first["bm25_score"] >= 0
    assert first["vector_score"] > 0


def test_jsonld_export_respects_role_access(tmp_path):
    db_path = build_test_db(tmp_path)
    with connect(db_path) as conn:
        external = export_jsonld(conn, role="external_partner", limit=500)
        researcher = export_jsonld(conn, role="researcher", limit=500)

    assert len(researcher["@graph"]) > len(external["@graph"])
    assert external["@graph"]
    assert external["@context"]["rdkg"].endswith("/ontology#")
    assert external["@context"]["uses_material"]["@id"] == "rdkg:uses_material"
    assert {"subject", "predicate", "object", "confidence"} <= set(external["@graph"][0])


def test_rdf_turtle_export_respects_role_access(tmp_path):
    db_path = build_test_db(tmp_path)
    with connect(db_path) as conn:
        external = export_rdf_turtle(conn, role="external_partner", limit=500)
        researcher = export_rdf_turtle(conn, role="researcher", limit=500)

    assert "@prefix rdkg:" in researcher
    assert "rdkg:RelationAssertion" in researcher
    assert len(researcher) > len(external)


def test_graph_supports_four_hop_traversal(tmp_path):
    db_path = tmp_path / "graph_depth.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "Traversal source", "confidentiality": "internal"})
        names = ["A", "B", "C", "D", "E"]
        entity_ids = [upsert_entity(conn, "Process", name, name.lower()) for name in names]
        for left, right in zip(entity_ids, entity_ids[1:]):
            insert_edge(conn, source_id, left, "describes", right, confidence=0.8, evidence="depth edge")

        depth_2 = get_graph(conn, "a", role="researcher", depth=2, limit=20)
        depth_4 = get_graph(conn, "a", role="researcher", depth=4, limit=20)

    assert "E" not in {node["name"] for node in depth_2["nodes"]}
    assert "E" in {node["name"] for node in depth_4["nodes"]}


def test_numeric_condition_overlap_converts_units():
    fact = {
        "property": "tds",
        "comparator": "<=",
        "numeric_value": 1000.0,
        "unit": "mg_l",
    }
    query_filter = {
        "property": "tds",
        "comparator": "<=",
        "value": 1.0,
        "unit": "g_l",
    }

    assert _condition_overlap(query_filter, fact) is True


def test_numeric_condition_overlap_accepts_unit_aliases_and_engineering_conversions():
    assert _condition_overlap(
        {"property": "tds", "comparator": "<=", "value": 1.0, "unit": "г/л"},
        {"property": "tds", "comparator": "<=", "numeric_value": 1000.0, "unit": "мг/дм3"},
    )
    assert _condition_overlap(
        {"property": "flow_rate", "comparator": "=", "value": 1.0, "unit": "л/с"},
        {"property": "flow_rate", "comparator": "=", "numeric_value": 3.6, "unit": "m3/h"},
    )
    assert _condition_overlap(
        {"property": "throughput", "comparator": ">=", "value": 2000.0, "unit": "kg/day"},
        {"property": "throughput", "comparator": ">=", "numeric_value": 2.0, "unit": "т/сут"},
    )


def test_strict_numeric_filters_keep_matching_facts_only(tmp_path):
    db_path = build_test_db(tmp_path)
    request = SearchRequest(
        query="обессоливание шахтных вод",
        numeric_filters=[NumericFilter(property="tds", comparator="<=", value=1.0, unit="g_l")],
        strict_numeric_filters=True,
        top_k=5,
    )

    with connect(db_path) as conn:
        result = run_search(conn, request, role="researcher")

    assert result["facts"]
    assert all(fact.get("numeric_match") for fact in result["facts"])
    assert {fact.get("property") for fact in result["facts"]} <= {"tds"}
