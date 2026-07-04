from app.db import connect
from app.models import SearchRequest
from app.search import run_search
from app.seed_data import rebuild_demo_database
from app.synthesize import attach_answer, synthesize_answer


def test_synthesize_comparison_mode_includes_table():
    text = synthesize_answer(
        {
            "answer_mode": "comparison",
            "parsed_query": {},
            "sources": [{"title": "Source A", "reliability_score": 0.8}],
            "facts": [
                {
                    "id": 1,
                    "predicate": "has_numeric_condition",
                    "property": "tds",
                    "comparator": "<=",
                    "numeric_value": 1000,
                    "unit": "mg_l",
                    "source_title": "Source A",
                    "confidence": 0.8,
                    "evidence": "tds <=1000 mg/l",
                }
            ],
            "experiments": [],
            "experts": [],
            "gaps": [],
            "contradictions": [],
        }
    )

    assert "### Таблица сравнения" in text
    assert "| Параметр | Значение | Источник | Confidence | Доказательство |" in text
    assert "tds" in text


def test_synthesize_evidence_table_mode_includes_fact_status():
    text = synthesize_answer(
        {
            "answer_mode": "evidence_table",
            "parsed_query": {},
            "sources": [],
            "facts": [
                {
                    "id": 7,
                    "predicate": "has_numeric_condition",
                    "numeric_value": 0.2,
                    "unit": "m_s",
                    "source_title": "Patent",
                    "evidence_locator": "page 2",
                    "validation_status": "valid",
                }
            ],
            "experiments": [],
            "experts": [],
            "gaps": [],
            "contradictions": [],
        }
    )

    assert "### Evidence table" in text
    assert "| Fact ID | Predicate | Value | Source | Locator | Status |" in text
    assert "page 2" in text


def test_run_search_auto_selects_gap_analysis_mode(tmp_path):
    db_path = tmp_path / "rd_knowledge_test.sqlite"
    rebuild_demo_database(db_path)

    with connect(db_path) as conn:
        payload = run_search(
            conn,
            SearchRequest(query="Есть ли пробелы по комбинации холодный климат + кучное выщелачивание + никелевая руда?"),
            role="researcher",
        )

    answer = attach_answer(payload)
    assert answer["answer_mode"] == "gap_analysis"
    assert "### Gap analysis" in answer["answer_markdown"]
