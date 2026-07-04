from app.converters import ConversionCapabilities
from app.db import connect, create_schema, upsert_ingest_file
from scripts.corpus_progress import build_progress_report


def test_corpus_progress_splits_manifested_pending_and_failures(tmp_path, monkeypatch):
    def no_capabilities():
        return ConversionCapabilities(soffice=None, unrar=None, tesseract=None, ocrmypdf=None, seven_zip=None)

    monkeypatch.setattr("app.ingest.detect_conversion_capabilities", no_capabilities)
    monkeypatch.setattr("scripts.corpus_progress.detect_conversion_capabilities", no_capabilities)

    root = tmp_path / "corpus"
    root.mkdir()
    indexed = root / "indexed.pdf"
    failed = root / "failed.pdf"
    pending = root / "pending.doc"
    indexed.write_text("ok", encoding="utf-8")
    failed.write_text("", encoding="utf-8")
    pending.write_text("legacy", encoding="utf-8")
    db_path = tmp_path / "test.sqlite"

    with connect(db_path) as conn:
        create_schema(conn)
        upsert_ingest_file(conn, str(indexed), ".pdf", indexed.stat().st_size, "indexed", checksum="a")
        upsert_ingest_file(conn, str(failed), ".pdf", failed.stat().st_size, "failed", error="No extractable text chunks")

    report = build_progress_report(root, db_path=db_path, sample_limit=2)

    assert report["inventory"]["files"] == 3
    assert report["manifest"]["root_exact_files_manifested"] == 2
    assert report["manifest"]["root_exact_files_indexed_like"] == 1
    assert report["pending"]["files"] == 1
    assert report["pending"]["by_status"] == {"unsupported": 1}
    assert report["failures"]["by_error"] == {"No extractable text chunks": 1}
    assert report["remediation"]["pending_actions"] == {"install_soffice_for_legacy_office": 1}
    assert report["remediation"]["manifest_retry_actions"] == {"requires_ocr_for_failed_document": 1}


def test_corpus_progress_routes_mislabeled_image_to_ocr(tmp_path, monkeypatch):
    def with_soffice():
        return ConversionCapabilities(soffice="/usr/bin/soffice", unrar=None, tesseract=None, ocrmypdf=None, seven_zip=None)

    monkeypatch.setattr("app.ingest.detect_conversion_capabilities", with_soffice)
    monkeypatch.setattr("scripts.corpus_progress.detect_conversion_capabilities", with_soffice)

    root = tmp_path / "corpus"
    root.mkdir()
    mislabeled = root / "forecast.xls"
    mislabeled.write_bytes(b"BM" + b"\x00" * 64)
    db_path = tmp_path / "test.sqlite"

    with connect(db_path) as conn:
        create_schema(conn)
        upsert_ingest_file(
            conn,
            str(mislabeled),
            ".xls",
            mislabeled.stat().st_size,
            "skipped_unsupported",
            error="BMP image files require OCR/image extraction",
        )

    report = build_progress_report(root, db_path=db_path, sample_limit=2)

    assert report["remediation"]["manifest_retry_actions"] == {"wait_for_image_ocr_pipeline": 1}
