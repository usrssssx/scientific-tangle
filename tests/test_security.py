from app.db import (
    connect,
    create_schema,
    insert_audit,
    insert_document_chunk,
    insert_edge,
    insert_fact,
    insert_source,
    open_fact_dispute,
    review_fact,
    upsert_entity,
)
from app.models import SearchRequest
from app.search import dashboard_metrics, export_jsonld, get_graph, run_search
from app.security import AccessContext, can_access, can_access_source, can_export_confidentiality, dlp_sanitize, evaluate_export_policy


def test_dlp_redacts_paths_contacts_and_secrets_for_non_privileged_roles():
    payload = {
        "path": "/restricted/corpus/source.pdf",
        "contact": "expert@example.com",
        "api_key": "should-not-leak",
        "note": "Call +7 495 123-45-67 with token=secret123; keep 0.15-0.30 m/s at 2026-07-04 12:54:06",
    }

    sanitized = dlp_sanitize(payload, AccessContext(role="researcher"), export=True)
    privileged = dlp_sanitize(payload, AccessContext(role="analyst"), export=True)

    assert sanitized["path"] == "[redacted-path]"
    assert sanitized["contact"] == "[redacted-contact]"
    assert "[redacted-phone]" in sanitized["note"]
    assert "[redacted-secret]" in sanitized["note"]
    assert "0.15-0.30 m/s" in sanitized["note"]
    assert "2026-07-04 12:54:06" in sanitized["note"]
    assert privileged["path"] == payload["path"]
    assert privileged["contact"] == payload["contact"]
    assert privileged["api_key"] == "[redacted-secret]"
    assert "[redacted-secret]" in privileged["note"]


def test_can_access_source_enforces_department_project_and_admin_override():
    source = {
        "confidentiality": "internal",
        "metadata": {
            "department": "hydro",
            "allowed_projects": ["alpha"],
        },
    }

    assert can_access_source(source, AccessContext(role="researcher", department="hydro", project="alpha"))
    assert not can_access_source(source, AccessContext(role="researcher", department="met", project="alpha"))
    assert not can_access_source(source, AccessContext(role="researcher", department="hydro", project="beta"))
    assert can_access_source(source, AccessContext(role="admin", department="met", project="beta"))


def test_export_policy_is_stricter_than_view_access_for_secret_data():
    payload = {
        "evidence_pack": {
            "facts": [
                {
                    "fact_id": 1,
                    "source_title": "Secret protocol",
                    "source_confidentiality": "secret",
                }
            ]
        }
    }

    manager = AccessContext(role="manager")
    admin = AccessContext(role="admin")
    denied = evaluate_export_policy(payload, manager, "pdf")
    allowed = evaluate_export_policy(payload, admin, "pdf")

    assert can_access("secret", manager)
    assert not can_export_confidentiality("secret", manager)
    assert not denied.allowed
    assert denied.max_confidentiality == "secret"
    assert "requires role admin" in denied.reason
    assert allowed.allowed
    assert allowed.audit_details()["max_confidentiality"] == "secret"


def test_search_graph_dashboard_and_jsonld_apply_abac_source_metadata(tmp_path):
    db_path = tmp_path / "security.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)
        hydro_source = insert_source(
            conn,
            {
                "title": "Hydro nickel note",
                "source_type": "test",
                "confidentiality": "internal",
                "department": "hydro",
                "year": 2018,
            },
            path="/restricted/hydro.pdf",
        )
        met_source = insert_source(
            conn,
            {
                "title": "Met nickel note",
                "source_type": "test",
                "confidentiality": "internal",
                "department": "met",
                "year": 2026,
            },
            path="/restricted/met.pdf",
        )
        hydro_doc = insert_document_chunk(conn, hydro_source, 0, "nickel catholyte flow velocity 0.20 m/s", locator="page 1")
        met_doc = insert_document_chunk(conn, met_source, 0, "nickel catholyte flow velocity 0.90 m/s", locator="page 1")
        nickel = upsert_entity(conn, "Material", "nickel", "nickel")
        catholyte = upsert_entity(conn, "Process", "catholyte circulation", "catholyte_circulation")
        hydro_fact_id = insert_fact(
            conn,
            hydro_source,
            nickel,
            "recommended_condition",
            catholyte,
            property_="flow_velocity",
            numeric_value=0.2,
            unit="m_s",
            document_id=hydro_doc,
            evidence="nickel catholyte flow velocity 0.20 m/s",
            evidence_locator="page 1",
        )
        insert_fact(
            conn,
            met_source,
            nickel,
            "recommended_condition",
            catholyte,
            property_="flow_velocity",
            numeric_value=0.9,
            unit="m_s",
            document_id=met_doc,
            evidence="nickel catholyte flow velocity 0.90 m/s",
            evidence_locator="page 1",
        )
        insert_edge(conn, hydro_source, nickel, "uses_process", catholyte, confidence=0.8, evidence="hydro edge")
        insert_edge(conn, met_source, nickel, "uses_process", catholyte, confidence=0.8, evidence="met edge")
        review_fact(conn, hydro_fact_id, reviewer="lead", role="analyst", action="verify")
        open_fact_dispute(
            conn,
            hydro_fact_id,
            opened_by="expert-a",
            role="analyst",
            reason="Conflicting protocol",
            severity="high",
            assignee="lead",
            due_at="2000-01-01 00:00:00",
        )
        insert_audit(conn, "export_table", "researcher", object_type="query", object_id="nickel")

        context = AccessContext(role="researcher", department="hydro")
        result = run_search(conn, SearchRequest(query="nickel catholyte flow velocity", top_k=10), role=context)
        titles = {source["title"] for source in result["sources"]}
        fact_sources = {fact["source_title"] for fact in result["facts"]}
        graph = get_graph(conn, "nickel", role=context)
        dashboard = dashboard_metrics(conn, role=context)
        jsonld = export_jsonld(conn, role=context, limit=10)

    assert titles == {"Hydro nickel note"}
    assert fact_sources == {"Hydro nickel note"}
    assert {edge["source_id"] for edge in graph["edges"]} == {hydro_source}
    assert sum(item["count"] for item in dashboard["sources_by_type"]) == 1
    assert dashboard["manager_summary"]["sources"] == 1
    assert dashboard["manager_summary"]["facts"] == 1
    assert dashboard["manager_summary"]["verified_facts"] == 0
    assert dashboard["manager_summary"]["contradicted_facts"] == 1
    assert dashboard["manager_summary"]["open_disputes"] == 1
    assert dashboard["manager_summary"]["overdue_disputes"] == 1
    assert dashboard["manager_summary"]["stale_sources"] == 1
    assert dashboard["fact_status_counts"] == [{"status": "contradicted", "count": 1}]
    assert dashboard["overdue_disputes"][0]["source_title"] == "Hydro nickel note"
    assert dashboard["team_activity"][0]["reviewer"] in {"expert-a", "lead"}
    assert any(item["action"] == "export_table" for item in dashboard["audit_activity"])
    assert {edge["uses_process"]["source"] for edge in jsonld["@graph"]} == {hydro_source}
