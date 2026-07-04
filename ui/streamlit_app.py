from __future__ import annotations

import json
import os

import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("RD_KG_API_URL", "http://localhost:8000")
API_KEY = os.getenv("RD_KG_API_KEY")

st.set_page_config(page_title="R&D Knowledge Map MVP", layout="wide")
st.title("Карта знаний R&D: горно-металлургический MVP")

role = st.sidebar.selectbox("Роль", ["researcher", "analyst", "manager", "admin", "external_partner"], index=0)
include_internal = st.sidebar.checkbox("Показывать внутренние источники", value=True)


def api_headers() -> dict[str, str]:
    headers = {"X-Role": role}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    return headers

try:
    demo_questions = requests.get(f"{API_URL}/demo/questions", timeout=5).json()["questions"]
except Exception:
    demo_questions = [
        "Какие методы обессоливания воды подходят для обогатительной фабрики, если исходная вода содержит сульфаты, хлориды, Ca, Mg, Na по 200–300 мг/л, а требуемый сухой остаток — ≤1000 мг/дм³?"
    ]

selected = st.selectbox("Демо-вопрос", ["Свой вопрос"] + demo_questions)
query_default = "" if selected == "Свой вопрос" else selected
query = st.text_area("Запрос на естественном языке", value=query_default, height=100)

mode_col, topk_col, conf_col = st.columns(3)
with mode_col:
    answer_mode = st.selectbox("Режим ответа", ["auto", "review", "comparison", "protocol", "gap_analysis", "evidence_table"], index=0)
with topk_col:
    top_k = st.slider("Top K", min_value=3, max_value=25, value=10, step=1)
with conf_col:
    min_confidence = st.slider("Min confidence", min_value=0.0, max_value=1.0, value=0.0, step=0.05)

col1, col2, col3 = st.columns(3)
with col1:
    year_from = st.number_input("Год от", min_value=1900, max_value=2100, value=2020)
with col2:
    year_to = st.number_input("Год до", min_value=1900, max_value=2100, value=2026)
with col3:
    use_year = st.checkbox("Применить фильтр годов", value=False)

geography = st.multiselect("География", ["russia", "foreign", "canada", "finland", "chile", "kazakhstan"])

with st.expander("Числовой фильтр"):
    use_numeric_filter = st.checkbox("Применить числовой фильтр", value=False)
    strict_numeric_filters = st.checkbox("Только совпавшие числовые факты", value=False)
    nf_col1, nf_col2, nf_col3, nf_col4 = st.columns(4)
    with nf_col1:
        numeric_property = st.selectbox(
            "Свойство",
            [
                "tds",
                "flow_velocity",
                "recovery",
                "temperature",
                "cost",
                "capex",
                "opex",
                "calcium_concentration",
                "magnesium_concentration",
                "sodium_concentration",
                "sulfate_concentration",
                "chloride_concentration",
            ],
        )
    with nf_col2:
        comparator = st.selectbox("Оператор", ["<=", ">=", "=", "between"], index=0)
    with nf_col3:
        numeric_value = st.number_input("Значение", value=1.0, disabled=comparator == "between")
        min_value = st.number_input("Min", value=0.0, disabled=comparator != "between")
    with nf_col4:
        unit = st.selectbox("Единица", ["mg_l", "g_l", "m_s", "percent", "celsius", "t_day", "kg_day", "m3_h", "m3_day", "l_s", "rub_m3", "usd_m3", "ph"])
        max_value = st.number_input("Max", value=1.0, disabled=comparator != "between")

if st.button("Найти и синтезировать ответ", type="primary"):
    numeric_filters = []
    if use_numeric_filter:
        numeric_filter = {"property": numeric_property, "comparator": comparator, "unit": unit}
        if comparator == "between":
            numeric_filter["min_value"] = float(min_value)
            numeric_filter["max_value"] = float(max_value)
        else:
            numeric_filter["value"] = float(numeric_value)
        numeric_filters.append(numeric_filter)
    payload = {
        "query": query,
        "answer_mode": answer_mode,
        "include_internal": include_internal,
        "top_k": int(top_k),
        "min_confidence": float(min_confidence),
        "geography": geography or None,
        "year_from": int(year_from) if use_year else None,
        "year_to": int(year_to) if use_year else None,
        "numeric_filters": numeric_filters,
        "strict_numeric_filters": bool(strict_numeric_filters),
    }
    with st.spinner("Выполняю поиск по документам, графу и экспериментам"):
        resp = requests.post(f"{API_URL}/search", json=payload, headers=api_headers(), timeout=60)
    if resp.status_code >= 400:
        st.error(resp.text)
    else:
        data = resp.json()
        st.caption(f"Answer mode: {data.get('answer_mode', answer_mode)}")
        st.markdown(data["answer_markdown"])
        with st.expander("Parsed query / JSON"):
            st.json(data["parsed_query"])
        if data.get("sources"):
            st.subheader("Источники")
            st.dataframe(pd.DataFrame(data["sources"])[["title", "source_type", "year", "geography", "confidentiality", "reliability_score", "score"]])
        if data.get("facts"):
            st.subheader("Факты")
            fact_cols = [
                "id",
                "status",
                "validation_status",
                "predicate",
                "property",
                "comparator",
                "numeric_value",
                "min_value",
                "max_value",
                "unit",
                "confidence",
                "extraction_confidence",
                "source_title",
                "evidence_locator",
                "evidence_start",
                "evidence_end",
            ]
            st.dataframe(pd.DataFrame(data["facts"])[[c for c in fact_cols if c in pd.DataFrame(data["facts"]).columns]])
        if data.get("evidence_pack"):
            with st.expander("Evidence pack"):
                st.json(data["evidence_pack"])
        if data.get("experiments"):
            st.subheader("Эксперименты")
            st.dataframe(pd.DataFrame(data["experiments"]))
        st.download_button(
            "Скачать ответ JSON",
            data=json.dumps(data, ensure_ascii=False, indent=2),
            file_name="rd_knowledge_answer.json",
            mime="application/json",
        )

st.sidebar.divider()
if st.sidebar.button("Dashboard"):
    resp = requests.get(f"{API_URL}/dashboard", headers=api_headers(), timeout=30)
    if resp.status_code >= 400:
        st.sidebar.error(resp.text)
    else:
        metrics = resp.json()
        st.subheader("Dashboard")
        summary = metrics.get("manager_summary", {})
        cols = st.columns(4)
        with cols[0]:
            st.metric("Sources", summary.get("sources", sum(item.get("count", 0) for item in metrics.get("sources_by_type", []))))
        with cols[1]:
            st.metric("Facts", summary.get("facts", 0))
        with cols[2]:
            st.metric("Open disputes", summary.get("open_disputes", 0))
        with cols[3]:
            st.metric("Overdue", summary.get("overdue_disputes", 0))
        dashboard_tabs = st.tabs(["Coverage", "Quality", "Freshness", "Activity"])
        with dashboard_tabs[0]:
            st.dataframe(pd.DataFrame(metrics.get("sources_by_type", [])), use_container_width=True)
            st.dataframe(pd.DataFrame(metrics.get("entities_by_type", [])), use_container_width=True)
            st.dataframe(pd.DataFrame(metrics.get("fact_coverage_by_property", [])), use_container_width=True)
        with dashboard_tabs[1]:
            st.dataframe(pd.DataFrame(metrics.get("fact_status_counts", [])), use_container_width=True)
            st.dataframe(pd.DataFrame(metrics.get("validation_status_counts", [])), use_container_width=True)
            st.dataframe(pd.DataFrame(metrics.get("disputes_by_severity", [])), use_container_width=True)
            st.dataframe(pd.DataFrame(metrics.get("overdue_disputes", [])), use_container_width=True)
        with dashboard_tabs[2]:
            st.dataframe(pd.DataFrame(metrics.get("source_freshness_by_year", [])), use_container_width=True)
            st.dataframe(pd.DataFrame(metrics.get("stale_sources", [])), use_container_width=True)
            st.dataframe(pd.DataFrame(metrics.get("risk_zones_low_connectivity", [])), use_container_width=True)
        with dashboard_tabs[3]:
            st.dataframe(pd.DataFrame(metrics.get("team_activity", [])), use_container_width=True)
            st.dataframe(pd.DataFrame(metrics.get("audit_activity", [])), use_container_width=True)

st.sidebar.divider()
show_curation = role in {"analyst", "admin"} and st.sidebar.checkbox("Кураторская панель", value=False)
if show_curation:
    st.subheader("Кураторская проверка фактов")
    curation_limit = st.slider("Размер очереди", min_value=5, max_value=100, value=25, step=5)
    assignee_filter = st.text_input("Фильтр по assignee")
    pending_params = {"limit": int(curation_limit)}
    if assignee_filter.strip():
        pending_params["assignee"] = assignee_filter.strip()
    resp = requests.get(f"{API_URL}/curation/facts/pending", params=pending_params, headers=api_headers(), timeout=30)
    if resp.status_code >= 400:
        st.error(resp.text)
    else:
        facts = resp.json()
        if not facts:
            st.info("Нет фактов в очереди.")
        else:
            df = pd.DataFrame(facts)
            visible_cols = [
                c
                for c in [
                    "id",
                    "status",
                    "validation_status",
                    "predicate",
                    "property",
                    "numeric_value",
                    "min_value",
                    "max_value",
                    "unit",
                    "confidence",
                    "extraction_confidence",
                    "source_title",
                    "evidence_locator",
                    "assignee",
                    "assignment_due_at",
                ]
                if c in df.columns
            ]
            st.dataframe(df[visible_cols], use_container_width=True)
            options = [int(item["id"]) for item in facts]
            selected_fact_id = st.selectbox("Факт для проверки", options=options, format_func=lambda value: f"fact #{value}")
            selected_fact = next(item for item in facts if int(item["id"]) == int(selected_fact_id))
            evidence_label = selected_fact.get("source_title") or "Источник"
            if selected_fact.get("evidence_locator"):
                evidence_label += f" · {selected_fact['evidence_locator']}"
            if selected_fact.get("evidence_start") is not None and selected_fact.get("evidence_end") is not None:
                evidence_label += f" · span {selected_fact['evidence_start']}-{selected_fact['evidence_end']}"
            st.caption(evidence_label)
            st.write(selected_fact.get("evidence") or selected_fact.get("value_text") or "")

            history_col, supersede_col = st.columns(2)
            with history_col:
                if st.button("Показать историю факта"):
                    history_resp = requests.get(f"{API_URL}/curation/facts/{selected_fact_id}/history", headers=api_headers(), timeout=30)
                    if history_resp.status_code >= 400:
                        st.error(history_resp.text)
                    else:
                        st.json(history_resp.json())
            with supersede_col:
                replacement_fact_id = st.number_input("Replacement fact id", min_value=1, value=int(selected_fact_id) + 1, step=1)
                if st.button("Supersede selected", disabled=int(replacement_fact_id) == int(selected_fact_id)):
                    supersede_payload = {
                        "replacement_fact_id": int(replacement_fact_id),
                        "reviewer": "demo-expert",
                        "comment": "superseded from curation UI",
                    }
                    supersede_resp = requests.post(
                        f"{API_URL}/curation/facts/{selected_fact_id}/supersede",
                        json=supersede_payload,
                        headers=api_headers(),
                        timeout=30,
                    )
                    if supersede_resp.status_code >= 400:
                        st.error(supersede_resp.text)
                    else:
                        st.success("Supersede chain сохранён")
                        st.json(supersede_resp.json())

            review_col1, review_col2 = st.columns([1, 2])
            with review_col1:
                action = st.selectbox(
                    "Действие",
                    ["verify", "reject", "comment", "mark_contradicted", "mark_superseded"],
                    index=0,
                )
                reviewer = st.text_input("Рецензент", value="demo-expert")
            with review_col2:
                comment = st.text_area("Комментарий", height=100)
            if st.button("Сохранить проверку", type="primary"):
                payload = {"action": action, "reviewer": reviewer, "comment": comment or None}
                review_resp = requests.post(
                    f"{API_URL}/curation/facts/{selected_fact_id}/review",
                    json=payload,
                    headers=api_headers(),
                    timeout=30,
                )
                if review_resp.status_code >= 400:
                    st.error(review_resp.text)
                else:
                    st.success("Проверка сохранена")
                    st.json(review_resp.json())

            st.divider()
            st.subheader("Dispute workflow")
            dispute_col1, dispute_col2, dispute_col3 = st.columns(3)
            with dispute_col1:
                dispute_reason = st.text_input("Причина спора", value="")
            with dispute_col2:
                dispute_severity = st.selectbox("Severity", ["low", "medium", "high", "critical"], index=1)
            with dispute_col3:
                dispute_due_at = st.text_input("Dispute due at", value=assignment_due_at if "assignment_due_at" in locals() else "")
            dispute_assignee = st.text_input("Dispute assignee", value=assignee_filter.strip() or reviewer)
            if st.button("Открыть dispute", disabled=not dispute_reason.strip()):
                dispute_payload = {
                    "reason": dispute_reason.strip(),
                    "severity": dispute_severity,
                    "reviewer": reviewer,
                    "assignee": dispute_assignee.strip() or None,
                    "due_at": dispute_due_at.strip() or None,
                    "comment": comment or None,
                }
                dispute_resp = requests.post(
                    f"{API_URL}/curation/facts/{selected_fact_id}/dispute",
                    json=dispute_payload,
                    headers=api_headers(),
                    timeout=30,
                )
                if dispute_resp.status_code >= 400:
                    st.error(dispute_resp.text)
                else:
                    st.success("Dispute открыт")
                    st.json(dispute_resp.json())

            dispute_params = {"limit": int(curation_limit)}
            if assignee_filter.strip():
                dispute_params["assignee"] = assignee_filter.strip()
            disputes_resp = requests.get(f"{API_URL}/curation/disputes", params=dispute_params, headers=api_headers(), timeout=30)
            if disputes_resp.status_code >= 400:
                st.error(disputes_resp.text)
            else:
                disputes = disputes_resp.json()
                if disputes:
                    disputes_df = pd.DataFrame(disputes)
                    dispute_cols = [
                        c
                        for c in [
                            "id",
                            "fact_id",
                            "status",
                            "severity",
                            "sla_state",
                            "assignee",
                            "due_at",
                            "source_title",
                            "property",
                            "comments_count",
                        ]
                        if c in disputes_df.columns
                    ]
                    st.dataframe(disputes_df[dispute_cols], use_container_width=True)
                    selected_dispute_id = st.selectbox(
                        "Dispute для действия",
                        options=[int(item["id"]) for item in disputes],
                        format_func=lambda value: f"dispute #{value}",
                    )
                    dispute_action_col1, dispute_action_col2, dispute_action_col3 = st.columns(3)
                    with dispute_action_col1:
                        dispute_comment = st.text_input("Dispute comment")
                        if st.button("Add dispute comment", disabled=not dispute_comment.strip()):
                            comment_resp = requests.post(
                                f"{API_URL}/curation/disputes/{selected_dispute_id}/comment",
                                json={"author": reviewer, "comment": dispute_comment.strip()},
                                headers=api_headers(),
                                timeout=30,
                            )
                            if comment_resp.status_code >= 400:
                                st.error(comment_resp.text)
                            else:
                                st.success("Комментарий добавлен")
                    with dispute_action_col2:
                        escalation_assignee = st.text_input("Escalate to", value=dispute_assignee)
                        if st.button("Escalate dispute"):
                            escalate_resp = requests.post(
                                f"{API_URL}/curation/disputes/{selected_dispute_id}/escalate",
                                json={"reviewer": reviewer, "assignee": escalation_assignee.strip() or None, "comment": dispute_comment or None},
                                headers=api_headers(),
                                timeout=30,
                            )
                            if escalate_resp.status_code >= 400:
                                st.error(escalate_resp.text)
                            else:
                                st.success("Dispute эскалирован")
                                st.json(escalate_resp.json())
                    with dispute_action_col3:
                        resolution = st.text_input("Resolution")
                        resolution_status = st.selectbox("Fact status after resolution", ["", "candidate", "verified", "rejected", "contradicted", "superseded"])
                        if st.button("Resolve dispute", disabled=not resolution.strip()):
                            resolve_resp = requests.post(
                                f"{API_URL}/curation/disputes/{selected_dispute_id}/resolve",
                                json={
                                    "reviewer": reviewer,
                                    "resolution": resolution.strip(),
                                    "fact_status": resolution_status or None,
                                },
                                headers=api_headers(),
                                timeout=30,
                            )
                            if resolve_resp.status_code >= 400:
                                st.error(resolve_resp.text)
                            else:
                                st.success("Dispute закрыт")
                                st.json(resolve_resp.json())
                else:
                    st.info("Нет открытых disputes.")

            bulk_fact_ids = st.multiselect("Факты для bulk review", options=options, format_func=lambda value: f"fact #{value}")
            assign_col1, assign_col2 = st.columns(2)
            with assign_col1:
                assignee = st.text_input("Assignee", value=reviewer)
            with assign_col2:
                assignment_due_at = st.text_input("Due at", value="")
            assign_buttons = st.columns(3)
            with assign_buttons[0]:
                if st.button("Assign selected", disabled=not bulk_fact_ids or not assignee.strip()):
                    assign_payload = {
                        "fact_ids": [int(value) for value in bulk_fact_ids],
                        "assignee": assignee.strip(),
                        "reviewer": reviewer,
                        "due_at": assignment_due_at.strip() or None,
                        "comment": comment or None,
                    }
                    assign_resp = requests.post(f"{API_URL}/curation/facts/assign", json=assign_payload, headers=api_headers(), timeout=30)
                    if assign_resp.status_code >= 400:
                        st.error(assign_resp.text)
                    else:
                        st.success("Факты назначены")
                        st.json(assign_resp.json())
            with assign_buttons[1]:
                if st.button("Release assignment", disabled=not bulk_fact_ids):
                    release_payload = {
                        "fact_ids": [int(value) for value in bulk_fact_ids],
                        "reviewer": reviewer,
                        "comment": comment or None,
                    }
                    release_resp = requests.post(f"{API_URL}/curation/facts/release-assignment", json=release_payload, headers=api_headers(), timeout=30)
                    if release_resp.status_code >= 400:
                        st.error(release_resp.text)
                    else:
                        st.success("Назначение снято")
                        st.json(release_resp.json())
            if st.button("Bulk review selected", disabled=not bulk_fact_ids):
                bulk_payload = {
                    "fact_ids": [int(value) for value in bulk_fact_ids],
                    "action": action,
                    "reviewer": reviewer,
                    "comment": comment or None,
                }
                bulk_resp = requests.post(f"{API_URL}/curation/facts/bulk-review", json=bulk_payload, headers=api_headers(), timeout=30)
                if bulk_resp.status_code >= 400:
                    st.error(bulk_resp.text)
                else:
                    st.success("Bulk review сохранён")
                    st.json(bulk_resp.json())

            st.divider()
            st.subheader("Merge / split сущностей")
            merge_col1, merge_col2, merge_col3 = st.columns(3)
            with merge_col1:
                survivor_id = st.number_input("Survivor entity id", min_value=1, value=1, step=1)
            with merge_col2:
                duplicate_id = st.number_input("Duplicate entity id", min_value=1, value=2, step=1)
            with merge_col3:
                merge_comment = st.text_input("Merge comment")
            if st.button("Merge entities"):
                merge_payload = {
                    "survivor_id": int(survivor_id),
                    "duplicate_id": int(duplicate_id),
                    "reviewer": reviewer,
                    "comment": merge_comment or None,
                }
                merge_resp = requests.post(f"{API_URL}/curation/entities/merge", json=merge_payload, headers=api_headers(), timeout=30)
                if merge_resp.status_code >= 400:
                    st.error(merge_resp.text)
                else:
                    st.success("Сущности объединены")
                    st.json(merge_resp.json())

            split_col1, split_col2 = st.columns(2)
            with split_col1:
                source_entity_id = st.number_input("Source entity id", min_value=1, value=1, step=1)
                new_type = st.text_input("New entity type", value="Concept")
                new_name = st.text_input("New entity name")
                aliases_raw = st.text_input("Aliases, comma-separated")
            with split_col2:
                move_fact_ids_raw = st.text_input("Move fact IDs, comma-separated")
                move_edge_ids_raw = st.text_input("Move edge IDs, comma-separated")
                split_comment = st.text_area("Split comment", height=80)
            if st.button("Split entity"):
                def parse_ids(raw: str) -> list[int]:
                    return [int(part.strip()) for part in raw.split(",") if part.strip().isdigit()]

                split_payload = {
                    "source_entity_id": int(source_entity_id),
                    "new_type": new_type,
                    "new_name": new_name,
                    "aliases": [part.strip() for part in aliases_raw.split(",") if part.strip()],
                    "move_fact_ids": parse_ids(move_fact_ids_raw),
                    "move_edge_ids": parse_ids(move_edge_ids_raw),
                    "reviewer": reviewer,
                    "comment": split_comment or None,
                }
                split_resp = requests.post(f"{API_URL}/curation/entities/split", json=split_payload, headers=api_headers(), timeout=30)
                if split_resp.status_code >= 400:
                    st.error(split_resp.text)
                else:
                    st.success("Новая сущность создана")
                    st.json(split_resp.json())

st.sidebar.divider()
st.sidebar.subheader("Граф")
entity = st.sidebar.text_input("Сущность", value="catholyte_circulation")
if st.sidebar.button("Показать соседей"):
    resp = requests.post(f"{API_URL}/graph", json={"entity": entity, "depth": 2, "limit": 80}, headers=api_headers(), timeout=30)
    if resp.status_code >= 400:
        st.sidebar.error(resp.text)
    else:
        graph = resp.json()
        st.subheader(f"Соседи сущности: {entity}")
        st.write(f"Узлов: {len(graph['nodes'])}, связей: {len(graph['edges'])}")
        st.dataframe(pd.DataFrame(graph["nodes"]))
        st.dataframe(pd.DataFrame(graph["edges"])[["subject_name", "predicate", "object_name", "confidence", "source_title"]])
