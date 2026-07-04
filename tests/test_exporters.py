import csv
import io
import zipfile
from contextlib import contextmanager

import app.main as main_module
import pytest
from app.exporters import EVIDENCE_CSV_FIELDS, answer_payload_to_pdf, evidence_pack_to_csv, report_package_to_zip
from app.security import AccessContext
from pypdf import PdfReader


def sample_payload():
    return {
        "query": "tds <=1000",
        "confidence": 0.82,
        "answer_markdown": "## Answer\n\n- Source-backed finding from Source A.",
        "evidence_pack": {
            "facts": [
                {
                    "fact_id": 7,
                    "source_title": "Source A",
                    "source_year": 2026,
                    "locator": "chunk 1",
                    "span": [12, 34],
                    "predicate": "has_numeric_condition",
                    "subject": "desalination",
                    "object": None,
                    "value": {
                        "property": "tds",
                        "comparator": "<=",
                        "numeric_value": 1000.0,
                        "unit": "mg_l",
                    },
                    "confidence": 0.8,
                    "extraction_confidence": 0.7,
                    "validation_status": "valid",
                    "evidence": "TDS <=1000 mg/l",
                }
            ]
        },
    }


def test_evidence_pack_to_csv_exports_fact_trace_fields():
    payload = sample_payload()

    rows = list(csv.DictReader(io.StringIO(evidence_pack_to_csv(payload))))

    assert rows[0]["fact_id"] == "7"
    assert rows[0]["source_title"] == "Source A"
    assert rows[0]["locator"] == "chunk 1"
    assert rows[0]["span_start"] == "12"
    assert rows[0]["span_end"] == "34"
    assert rows[0]["property"] == "tds"
    assert rows[0]["numeric_value"] == "1000.0"
    assert rows[0]["evidence"] == "TDS <=1000 mg/l"


def test_evidence_pack_to_csv_returns_header_for_empty_pack():
    text = evidence_pack_to_csv({"evidence_pack": {"facts": []}})

    assert text.splitlines()[0].split(",") == EVIDENCE_CSV_FIELDS


def test_answer_payload_to_pdf_returns_valid_pdf():
    pdf_bytes = answer_payload_to_pdf(sample_payload())
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert pdf_bytes.startswith(b"%PDF")
    assert len(reader.pages) >= 1
    assert "Evidence Report" in text
    assert "Source A" in text


def test_report_package_to_zip_contains_markdown_csv_payload_and_pdf():
    package_bytes = report_package_to_zip(sample_payload())

    with zipfile.ZipFile(io.BytesIO(package_bytes)) as package:
        names = set(package.namelist())
        payload_text = package.read("payload.json").decode("utf-8")
        pdf_bytes = package.read("report.pdf")

    assert names == {"answer.md", "evidence.csv", "payload.json", "report.pdf"}
    assert "Source A" in payload_text
    assert pdf_bytes.startswith(b"%PDF")


def test_export_table_endpoint_audits_and_returns_csv(monkeypatch):
    audit_events = []
    payload = {
        "evidence_pack": {
            "facts": [
                {
                    "fact_id": 1,
                    "source_title": "Source A",
                    "locator": "chunk 1",
                    "span": [0, 10],
                    "value": {"property": "tds", "numeric_value": 1000.0},
                }
            ]
        }
    }

    @contextmanager
    def fake_connect():
        yield object()

    def fake_audit(conn, action, role, object_type=None, object_id=None, details=None):
        audit_events.append(
            {"action": action, "role": role, "object_type": object_type, "object_id": object_id, "details": details}
        )

    monkeypatch.setattr(main_module, "ensure_ready_or_503", lambda: None)
    monkeypatch.setattr(main_module, "connect", fake_connect)
    monkeypatch.setattr(main_module, "insert_audit", fake_audit)
    monkeypatch.setattr(main_module, "run_search", lambda conn, request, role: payload)
    monkeypatch.setattr(main_module, "attach_answer", lambda item: item)

    response = main_module.export_table("tds <=1000", context=AccessContext(role="researcher"))
    body = response.body.decode("utf-8")

    assert response.media_type == "text/csv"
    assert "source_title" in body
    assert "Source A" in body
    assert audit_events == [
        {
            "action": "export_table",
            "role": "researcher",
            "object_type": "query",
            "object_id": "tds <=1000",
            "details": {
                "format": "csv",
                "top_k": 10,
                "answer_mode": "evidence_table",
                "dlp": "role-aware",
                "export_policy": {
                    "allowed": True,
                    "format": "csv",
                    "role": "researcher",
                    "max_confidentiality": "public",
                    "classifications": [],
                    "reason": "allowed",
                },
            },
        }
    ]


def test_export_pdf_endpoint_audits_and_returns_pdf(monkeypatch):
    audit_events = []

    @contextmanager
    def fake_connect():
        yield object()

    def fake_audit(conn, action, role, object_type=None, object_id=None, details=None):
        audit_events.append(
            {"action": action, "role": role, "object_type": object_type, "object_id": object_id, "details": details}
        )

    monkeypatch.setattr(main_module, "ensure_ready_or_503", lambda: None)
    monkeypatch.setattr(main_module, "connect", fake_connect)
    monkeypatch.setattr(main_module, "insert_audit", fake_audit)
    monkeypatch.setattr(main_module, "run_search", lambda conn, request, role: sample_payload())
    monkeypatch.setattr(main_module, "attach_answer", lambda item: item)

    response = main_module.export_pdf("tds <=1000", context=AccessContext(role="researcher"))

    assert response.media_type == "application/pdf"
    assert response.body.startswith(b"%PDF")
    assert audit_events[0]["action"] == "export_pdf"
    assert audit_events[0]["details"]["export_policy"]["allowed"] is True


def test_export_report_package_endpoint_returns_zip(monkeypatch):
    @contextmanager
    def fake_connect():
        yield object()

    monkeypatch.setattr(main_module, "ensure_ready_or_503", lambda: None)
    monkeypatch.setattr(main_module, "connect", fake_connect)
    monkeypatch.setattr(main_module, "insert_audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "run_search", lambda conn, request, role: sample_payload())
    monkeypatch.setattr(main_module, "attach_answer", lambda item: item)

    response = main_module.export_report_package("tds <=1000", context=AccessContext(role="researcher"))

    assert response.media_type == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.body)) as package:
        assert "report.pdf" in package.namelist()


def test_export_pdf_endpoint_blocks_secret_payload_for_manager_and_audits(monkeypatch):
    audit_events = []
    secret_payload = sample_payload()
    secret_payload["evidence_pack"]["facts"][0]["source_confidentiality"] = "secret"

    @contextmanager
    def fake_connect():
        yield object()

    def fake_audit(conn, action, role, object_type=None, object_id=None, details=None):
        audit_events.append(
            {"action": action, "role": role, "object_type": object_type, "object_id": object_id, "details": details}
        )

    monkeypatch.setattr(main_module, "ensure_ready_or_503", lambda: None)
    monkeypatch.setattr(main_module, "connect", fake_connect)
    monkeypatch.setattr(main_module, "insert_audit", fake_audit)
    monkeypatch.setattr(main_module, "run_search", lambda conn, request, role: secret_payload)
    monkeypatch.setattr(main_module, "attach_answer", lambda item: item)

    with pytest.raises(main_module.HTTPException) as exc_info:
        main_module.export_pdf("secret metallurgy protocol", context=AccessContext(role="manager"))

    assert exc_info.value.status_code == 403
    assert audit_events[0]["action"] == "export_pdf"
    assert audit_events[0]["details"]["export_policy"]["allowed"] is False
    assert audit_events[0]["details"]["export_policy"]["max_confidentiality"] == "secret"
