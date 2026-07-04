from scripts.evaluate_quality import _answer_metrics, _evidence_metrics, _source_recall


def test_source_recall_reports_hits_and_missing_titles():
    result = _source_recall(["Nickel patent landscape", "Mine water review"], ["patent", "heap leaching"])

    assert result["recall"] == 0.5
    assert result["hits"] == 1
    assert result["missing"] == ["heap leaching"]


def test_evidence_metrics_require_source_document_evidence_and_span():
    result = _evidence_metrics(
        {
            "evidence_pack": {
                "facts": [
                    {
                        "source_title": "Source A",
                        "document_id": 1,
                        "evidence": "temperature 85 C",
                        "span": [10, 26],
                        "locator": "page 1",
                    },
                    {
                        "source_title": "Source B",
                        "document_id": 2,
                        "evidence": "missing span",
                        "span": [None, None],
                    },
                ],
                "source_snippets": [
                    {"title": "Source A", "document_id": 1, "snippet": "temperature 85 C"},
                ],
            }
        }
    )

    assert result["evidence_trace_coverage"] == 0.5
    assert result["evidence_locator_coverage"] == 0.5
    assert result["source_snippet_coverage"] == 1.0


def test_answer_metrics_check_source_citation_coverage():
    result = _answer_metrics(
        {
            "query": "nickel",
            "answer_mode": "review",
            "parsed_query": {},
            "sources": [{"title": "Source A", "source_type": "publication", "reliability_score": 0.8}],
            "facts": [],
            "experiments": [],
            "experts": [],
            "gaps": [],
            "contradictions": [],
            "evidence_pack": {"facts": [{"source_title": "Source A"}]},
        }
    )

    assert result["answer_citation_coverage"] == 1.0
    assert result["unsupported_answer_markers"] == 0
