from app.db import (
    add_fact_dispute_comment,
    connect,
    create_schema,
    assign_facts,
    escalate_fact_dispute,
    fact_history,
    insert_edge,
    insert_fact,
    insert_source,
    list_fact_disputes,
    merge_entities,
    open_fact_dispute,
    release_fact_assignments,
    resolve_fact_dispute,
    review_fact,
    review_facts_bulk,
    split_entity,
    supersede_fact,
    upsert_entity,
)


def test_merge_entities_repoints_facts_and_edges(tmp_path):
    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "doc", "source_type": "test"})
        survivor_id = upsert_entity(conn, "Material", "nickel", "nickel", [])
        duplicate_id = upsert_entity(conn, "Material", "Ni", "ni", [])
        process_id = upsert_entity(conn, "Process", "leaching", "leaching", [])
        insert_fact(conn, source_id, duplicate_id, "has_numeric_condition", property_="recovery", numeric_value=50, unit="percent")
        insert_edge(conn, source_id, process_id, "uses_material", duplicate_id, 0.5, "evidence")

        merged = merge_entities(conn, survivor_id, duplicate_id, reviewer="tester", role="analyst")

        assert merged["id"] == survivor_id
        assert conn.execute("SELECT COUNT(*) FROM entities WHERE id = ?", (duplicate_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT subject_id FROM facts").fetchone()["subject_id"] == survivor_id
        assert conn.execute("SELECT object_id FROM graph_edges").fetchone()["object_id"] == survivor_id


def test_split_entity_creates_new_entity_and_moves_selected_fact(tmp_path):
    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "doc", "source_type": "test"})
        source_entity_id = upsert_entity(conn, "Material", "nickel", "nickel", [])
        fact_id = insert_fact(conn, source_id, source_entity_id, "has_numeric_condition", property_="recovery", numeric_value=50, unit="percent")

        new_entity = split_entity(
            conn,
            source_entity_id=source_entity_id,
            new_type="Material",
            new_name="nickel_ore",
            aliases=["никелевая руда"],
            reviewer="tester",
            role="analyst",
            move_fact_ids=[fact_id],
        )

        assert new_entity["name"] == "nickel_ore"
        assert conn.execute("SELECT subject_id FROM facts WHERE id = ?", (fact_id,)).fetchone()["subject_id"] == new_entity["id"]


def test_review_facts_bulk_reviews_unique_ids(tmp_path):
    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "doc", "source_type": "test"})
        entity_id = upsert_entity(conn, "Material", "nickel", "nickel", [])
        fact_id_1 = insert_fact(conn, source_id, entity_id, "has_numeric_condition", property_="recovery", numeric_value=50, unit="percent")
        fact_id_2 = insert_fact(conn, source_id, entity_id, "has_numeric_condition", property_="tds", numeric_value=1000, unit="mg_l")

        reviewed = review_facts_bulk(
            conn,
            [fact_id_1, fact_id_2, fact_id_1],
            reviewer="tester",
            role="analyst",
            action="verify",
            comment="batch ok",
        )

        assert [item["id"] for item in reviewed] == [fact_id_1, fact_id_2]
        assert conn.execute("SELECT COUNT(*) FROM fact_reviews").fetchone()[0] == 2
        statuses = {
            row["id"]: row["status"]
            for row in conn.execute("SELECT id, status FROM facts WHERE id IN (?, ?)", (fact_id_1, fact_id_2)).fetchall()
        }
        assert statuses == {fact_id_1: "verified", fact_id_2: "verified"}


def test_fact_assignment_release_and_review_completion(tmp_path):
    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "doc", "source_type": "test"})
        entity_id = upsert_entity(conn, "Material", "nickel", "nickel", [])
        fact_id_1 = insert_fact(conn, source_id, entity_id, "has_numeric_condition", property_="recovery", numeric_value=50, unit="percent")
        fact_id_2 = insert_fact(conn, source_id, entity_id, "has_numeric_condition", property_="tds", numeric_value=1000, unit="mg_l")

        assignments = assign_facts(
            conn,
            [fact_id_1, fact_id_2],
            assignee="expert-a",
            assigned_by="lead",
            role="analyst",
            due_at="2026-07-10",
        )

        assert [item["assignee"] for item in assignments] == ["expert-a", "expert-a"]
        release_fact_assignments(conn, [fact_id_1], reviewer="lead", role="analyst", comment="reassign later")
        review_fact(conn, fact_id_2, reviewer="expert-a", role="analyst", action="verify")

        statuses = {
            row["fact_id"]: row["status"]
            for row in conn.execute("SELECT fact_id, status FROM fact_assignments ORDER BY fact_id").fetchall()
        }
        assert statuses == {fact_id_1: "released", fact_id_2: "completed"}


def test_supersede_fact_links_replacement_and_history(tmp_path):
    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "doc", "source_type": "test"})
        entity_id = upsert_entity(conn, "Material", "nickel", "nickel", [])
        old_fact_id = insert_fact(conn, source_id, entity_id, "has_numeric_condition", property_="tds", numeric_value=1000, unit="mg_l")
        replacement_fact_id = insert_fact(conn, source_id, entity_id, "has_numeric_condition", property_="tds", numeric_value=900, unit="mg_l")

        replacement_history = supersede_fact(
            conn,
            fact_id=old_fact_id,
            replacement_fact_id=replacement_fact_id,
            reviewer="expert-a",
            role="analyst",
            comment="newer evidence",
        )
        old_history = fact_history(conn, old_fact_id)

        assert old_history["fact"]["status"] == "superseded"
        assert replacement_history["fact"]["supersedes_fact_id"] == old_fact_id
        assert replacement_history["supersedes"]["id"] == old_fact_id
        assert old_history["superseded_by"][0]["id"] == replacement_fact_id
        assert old_history["reviews"][0]["action"] == "mark_superseded"


def test_fact_dispute_workflow_tracks_comments_sla_escalation_and_resolution(tmp_path):
    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "doc", "source_type": "test"})
        entity_id = upsert_entity(conn, "Material", "nickel", "nickel", [])
        fact_id = insert_fact(conn, source_id, entity_id, "has_numeric_condition", property_="tds", numeric_value=1000, unit="mg_l")

        dispute = open_fact_dispute(
            conn,
            fact_id,
            opened_by="expert-a",
            role="analyst",
            reason="Conflicts with lab protocol",
            severity="high",
            assignee="lead",
            due_at="2000-01-01 00:00:00",
            comment="Initial evidence attached",
        )
        comment = add_fact_dispute_comment(conn, dispute["id"], author="lead", role="analyst", comment="Need second source")
        queue = list_fact_disputes(conn, limit=10)
        escalated = escalate_fact_dispute(
            conn,
            dispute["id"],
            reviewer="lead",
            role="analyst",
            assignee="principal",
            comment="SLA breached",
        )
        resolved = resolve_fact_dispute(
            conn,
            dispute["id"],
            reviewer="principal",
            role="analyst",
            resolution="Rejected conflicting extracted fact",
            fact_status="rejected",
        )
        history = fact_history(conn, fact_id)

        fact = conn.execute("SELECT status FROM facts WHERE id = ?", (fact_id,)).fetchone()

    assert dispute["status"] == "open"
    assert dispute["sla_state"] == "overdue"
    assert comment["comment"] == "Need second source"
    assert queue[0]["id"] == dispute["id"]
    assert queue[0]["comments_count"] == 2
    assert escalated["status"] == "escalated"
    assert escalated["assignee"] == "principal"
    assert resolved["status"] == "resolved"
    assert resolved["resolution"] == "Rejected conflicting extracted fact"
    assert fact["status"] == "rejected"
    assert history["disputes"][0]["comments"][0]["comment"] == "Initial evidence attached"
    assert history["disputes"][0]["comments"][1]["comment"] == "Need second source"
    assert {row["action"] for row in history["reviews"]} >= {"open_dispute", "resolve_dispute"}
