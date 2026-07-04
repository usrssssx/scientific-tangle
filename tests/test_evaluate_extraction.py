from scripts.evaluate_extraction import evaluate_case


def test_evaluate_case_scores_entities_and_numeric():
    result = evaluate_case(
        {
            "id": "sample",
            "text": "Циркуляция католита при электроэкстракции никеля: скорость циркуляции 0.20 м/с.",
            "expected_entities": [
                {"type": "Process", "canonical": "catholyte_circulation"},
                {"type": "Process", "canonical": "electrowinning"},
                {"type": "Material", "canonical": "nickel"},
                {"type": "Property", "canonical": "flow_velocity"},
            ],
            "expected_numeric": [
                {"property": "flow_velocity", "comparator": "=", "value": 0.2, "unit": "m_s"}
            ],
        }
    )

    assert result["passed"] is True
    assert result["entities"]["recall"] == 1.0
    assert result["numeric"]["recall"] == 1.0
    assert result["relations"]["f1"] == 1.0
