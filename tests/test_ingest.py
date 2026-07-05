import json
import zipfile
from pathlib import Path

from app.converters import ConversionCapabilities
from app.db import connect, create_schema, insert_document_chunk, insert_fact, insert_source, upsert_ingest_file
from app.ingest import diagnose_file, ingest_archive_file, ingest_document_file, ingest_folder, inventory_folder
from scripts.backfill_evidence_metadata import backfill


def no_conversion_capabilities() -> ConversionCapabilities:
    return ConversionCapabilities(soffice=None, unrar=None, tesseract=None, ocrmypdf=None, seven_zip=None)


def test_document_chunks_get_default_chunk_locator_and_facts_inherit_it(tmp_path):
    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "Plain source"})
        document_id = insert_document_chunk(conn, source_id, 0, "plain evidence text", start_char=0, end_char=19)
        fact_id = insert_fact(
            conn,
            source_id=source_id,
            subject_id=None,
            predicate="has_numeric_condition",
            document_id=document_id,
            evidence="plain evidence",
            evidence_start=0,
            evidence_end=14,
        )

        doc = conn.execute("SELECT locator_type, locator, metadata_json FROM documents WHERE id = ?", (document_id,)).fetchone()
        fact = conn.execute("SELECT evidence_locator FROM facts WHERE id = ?", (fact_id,)).fetchone()

    assert doc["locator_type"] == "chunk"
    assert doc["locator"] == "chunk 1"
    assert json.loads(doc["metadata_json"])["chunk"] == 1
    assert fact["evidence_locator"] == "chunk 1"


def test_insert_fact_derives_evidence_span_from_document(tmp_path):
    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "Curated source"})
        document_id = insert_document_chunk(
            conn,
            source_id,
            0,
            "first sentence. exact evidence text. final sentence.",
            start_char=100,
            end_char=150,
        )
        exact_fact_id = insert_fact(
            conn,
            source_id=source_id,
            subject_id=None,
            predicate="recommendation",
            document_id=document_id,
            evidence="exact evidence text",
        )
        curated_fact_id = insert_fact(
            conn,
            source_id=source_id,
            subject_id=None,
            predicate="recommendation",
            document_id=document_id,
            evidence="manual curated summary not copied from the chunk",
        )

        rows = conn.execute(
            """
            SELECT id, evidence_locator, evidence_start, evidence_end
            FROM facts
            WHERE id IN (?, ?)
            ORDER BY id
            """,
            (exact_fact_id, curated_fact_id),
        ).fetchall()

    exact, curated = rows
    assert exact["evidence_locator"] == "chunk 1"
    assert exact["evidence_start"] == 116
    assert exact["evidence_end"] == 135
    assert curated["evidence_locator"] == "chunk 1"
    assert curated["evidence_start"] == 100
    assert curated["evidence_end"] == 150


def test_backfill_adds_chunk_locator_to_legacy_documents_and_facts(tmp_path):
    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "Legacy source"})
        document_id = insert_document_chunk(conn, source_id, 2, "legacy evidence text", start_char=0, end_char=20)
        conn.execute("UPDATE documents SET locator_type = NULL, locator = NULL, metadata_json = '{}' WHERE id = ?", (document_id,))
        fact_id = insert_fact(
            conn,
            source_id=source_id,
            subject_id=None,
            predicate="has_numeric_condition",
            document_id=document_id,
            evidence="legacy evidence",
            evidence_start=0,
            evidence_end=15,
        )

        stats = backfill(conn, table_limit=0)
        doc = conn.execute("SELECT locator_type, locator, metadata_json FROM documents WHERE id = ?", (document_id,)).fetchone()
        fact = conn.execute("SELECT evidence_locator FROM facts WHERE id = ?", (fact_id,)).fetchone()

    assert stats["documents_locator_backfilled"] == 1
    assert stats["facts_locator_backfilled"] == 1
    assert doc["locator_type"] == "chunk"
    assert doc["locator"] == "chunk 3"
    assert json.loads(doc["metadata_json"])["chunk"] == 3
    assert fact["evidence_locator"] == "chunk 3"


def test_backfill_adds_fallback_span_for_curated_legacy_fact(tmp_path):
    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(conn, {"title": "Curated legacy source"})
        document_id = insert_document_chunk(conn, source_id, 0, "chunk body without curated wording", start_char=200, end_char=232)
        fact_id = insert_fact(
            conn,
            source_id=source_id,
            subject_id=None,
            predicate="recommendation",
            document_id=document_id,
            evidence="manual curated summary",
        )
        conn.execute(
            """
            UPDATE facts
            SET evidence_locator = NULL, evidence_start = NULL, evidence_end = NULL
            WHERE id = ?
            """,
            (fact_id,),
        )

        stats = backfill(conn, table_limit=0)
        fact = conn.execute(
            "SELECT evidence_locator, evidence_start, evidence_end FROM facts WHERE id = ?",
            (fact_id,),
        ).fetchone()

    assert stats["facts_evidence_fallback"] == 1
    assert fact["evidence_locator"] == "chunk 1"
    assert fact["evidence_start"] == 200
    assert fact["evidence_end"] == 232


def test_diagnose_mislabeled_image_by_magic_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr("app.ingest.detect_conversion_capabilities", no_conversion_capabilities)
    path = tmp_path / "forecast.xls"
    path.write_bytes(b"BM" + b"\x00" * 64)

    diagnostic = diagnose_file(path)

    assert diagnostic["status"] == "unsupported"
    assert diagnostic["suffix"] == ".xls"
    assert "OCR/image" in diagnostic["reason"]


def test_ingest_folder_resume_limit_counts_new_files_only(tmp_path, monkeypatch):
    root = tmp_path / "corpus"
    root.mkdir()
    indexed = root / "already.txt"
    candidate = root / "candidate.txt"
    indexed.write_text("old", encoding="utf-8")
    candidate.write_text("new", encoding="utf-8")

    def fake_ingest_document_file(conn, path: Path, defaults=None):
        return {
            "source_id": None,
            "title": path.stem,
            "chunks": 1,
            "entities_found": 0,
            "numeric_facts_found": 0,
            "checksum_sha256": f"sha-{path.name}",
        }

    monkeypatch.setattr("app.ingest.checksum_file", lambda path: f"sha-{path.name}")
    monkeypatch.setattr("app.ingest.ingest_document_file", fake_ingest_document_file)

    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        upsert_ingest_file(conn, str(indexed), ".txt", indexed.stat().st_size, "indexed")

        results = ingest_folder(conn, root, limit=1, resume=True)

        assert [item["status"] for item in results] == ["already_indexed", "indexed"]
        row = conn.execute("SELECT status FROM ingest_files WHERE path = ?", (str(candidate),)).fetchone()
        assert row["status"] == "indexed"


def test_ingest_folder_skips_checksum_duplicates(tmp_path, monkeypatch):
    root = tmp_path / "corpus"
    root.mkdir()
    original = root / "a.txt"
    duplicate = root / "b.txt"
    original.write_text("same", encoding="utf-8")
    duplicate.write_text("same", encoding="utf-8")

    def fail_ingest(*args, **kwargs):
        raise AssertionError("duplicate file should not be ingested")

    monkeypatch.setattr("app.ingest.checksum_file", lambda path: "same-checksum")
    monkeypatch.setattr("app.ingest.ingest_document_file", fail_ingest)

    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        upsert_ingest_file(conn, str(original), ".txt", original.stat().st_size, "indexed", checksum="same-checksum")

        results = ingest_folder(conn, root, limit=1, resume=True)

        assert [item["status"] for item in results] == ["already_indexed", "duplicate_skipped"]
        row = conn.execute("SELECT status FROM ingest_files WHERE path = ?", (str(duplicate),)).fetchone()
        assert row["status"] == "duplicate_skipped"


def test_ingest_folder_resume_skips_terminal_failures_without_counting_limit(tmp_path, monkeypatch):
    root = tmp_path / "corpus"
    root.mkdir()
    failed = root / "failed.pdf"
    unsupported = root / "legacy.doc"
    candidate = root / "candidate.txt"
    failed.write_text("", encoding="utf-8")
    unsupported.write_text("legacy", encoding="utf-8")
    candidate.write_text("new", encoding="utf-8")

    def fake_ingest_document_file(conn, path: Path, defaults=None):
        return {
            "source_id": None,
            "title": path.stem,
            "chunks": 1,
            "entities_found": 0,
            "numeric_facts_found": 0,
            "checksum_sha256": f"sha-{path.name}",
        }

    monkeypatch.setattr("app.ingest.checksum_file", lambda path: f"sha-{path.name}")
    monkeypatch.setattr("app.ingest.ingest_document_file", fake_ingest_document_file)

    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        upsert_ingest_file(conn, str(failed), ".pdf", failed.stat().st_size, "failed", error="needs OCR")
        upsert_ingest_file(conn, str(unsupported), ".doc", unsupported.stat().st_size, "skipped_unsupported", error="legacy")

        results = ingest_folder(conn, root, limit=1, resume=True)

        assert [item["status"] for item in results] == ["indexed", "already_failed", "already_unsupported"]
        row = conn.execute("SELECT status FROM ingest_files WHERE path = ?", (str(candidate),)).fetchone()
        assert row["status"] == "indexed"


def test_inventory_folder_reports_domains_years_sizes_and_duplicates(tmp_path, monkeypatch):
    monkeypatch.setattr("app.ingest.detect_conversion_capabilities", no_conversion_capabilities)
    root = tmp_path / "corpus"
    reports = root / "Доклады" / "2025"
    reviews = root / "Reviews"
    reports.mkdir(parents=True)
    reviews.mkdir(parents=True)
    first = reports / "nickel_2025.pdf"
    second = reviews / "nickel_2025.pdf"
    first.write_text("a", encoding="utf-8")
    second.write_text("a", encoding="utf-8")
    legacy = root / "legacy.xls"
    legacy.write_text("x", encoding="utf-8")

    report = inventory_folder(root, include_checksums=True, largest_limit=2)

    assert report["files"] == 3
    assert report["by_domain"]["Доклады"] == 1
    assert report["by_domain"]["Reviews"] == 1
    assert report["by_year"]["2025"] == 2
    assert report["by_language_hint"]["mixed"] >= 1
    assert report["status_counts"]["supported"] == 2
    assert report["status_counts"]["unsupported"] == 1
    assert report["duplicate_name_size_groups"][0]["count"] == 2
    assert report["checksum_duplicates"][0]["count"] == 2
    assert len(report["largest_files"]) == 2


def test_diagnose_file_uses_available_conversion_tools(tmp_path, monkeypatch):
    legacy_doc = tmp_path / "legacy.doc"
    legacy_xls = tmp_path / "legacy.xls"
    archive = tmp_path / "bundle.rar"
    auxiliary_archive = tmp_path / "bundle.part2.rar"
    split = tmp_path / "bundle.001"
    for path in [legacy_doc, legacy_xls, archive, auxiliary_archive, split]:
        path.write_bytes(b"x")

    monkeypatch.setattr(
        "app.ingest.detect_conversion_capabilities",
        lambda: ConversionCapabilities(
            soffice="/usr/bin/soffice",
            unrar="/usr/bin/unrar",
            tesseract=None,
            ocrmypdf=None,
            seven_zip="/usr/bin/7z",
        ),
    )

    assert diagnose_file(legacy_doc)["status"] == "supported"
    assert diagnose_file(legacy_xls)["status"] == "supported"
    assert diagnose_file(archive)["status"] == "supported_archive"
    auxiliary_diagnostic = diagnose_file(auxiliary_archive)
    assert auxiliary_diagnostic["status"] == "unsupported"
    assert "auxiliary multipart RAR volume" in auxiliary_diagnostic["reason"]
    split_diagnostic = diagnose_file(split)
    assert split_diagnostic["status"] == "unsupported"
    assert "missing later parts" in split_diagnostic["reason"]

    monkeypatch.setattr("app.ingest.detect_conversion_capabilities", no_conversion_capabilities)

    assert diagnose_file(legacy_doc)["status"] == "unsupported"
    assert diagnose_file(archive)["status"] == "unsupported"


def test_ingest_archive_file_routes_rar(tmp_path, monkeypatch):
    rar_path = tmp_path / "bundle.rar"
    rar_path.write_bytes(b"rar")
    extracted_root = tmp_path / "extracted"
    calls = {}

    def fake_extract_rar_archive(path: Path, target_dir: Path) -> Path:
        calls["archive_path"] = path
        calls["target_dir"] = target_dir
        extracted_root.mkdir()
        return extracted_root

    def fake_ingest_folder(conn, root: Path, defaults=None, **kwargs):
        calls["ingest_root"] = root
        calls["defaults"] = defaults
        calls["limit"] = kwargs.get("limit")
        return [{"status": "indexed", "path": str(root / "child.txt")}]

    monkeypatch.setattr("app.ingest.extract_rar_archive", fake_extract_rar_archive)
    monkeypatch.setattr("app.ingest.ingest_folder", fake_ingest_folder)

    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        result = ingest_archive_file(conn, rar_path, defaults={"source_type": "archive"}, limit=3)

    assert result == [{"status": "indexed", "path": str(extracted_root / "child.txt")}]
    assert calls["archive_path"] == rar_path
    assert calls["ingest_root"] == extracted_root
    assert calls["defaults"] == {"source_type": "archive"}
    assert calls["limit"] == 3


def test_diagnose_file_supports_consecutive_split_zip(tmp_path):
    original_zip = tmp_path / "bundle.zip"
    with zipfile.ZipFile(original_zip, "w") as zf:
        zf.writestr("child.txt", "payload")
    data = original_zip.read_bytes()
    original_zip.unlink()
    first_part = tmp_path / "bundle.zip.001"
    second_part = tmp_path / "bundle.zip.002"
    first_part.write_bytes(data[: len(data) // 2])
    second_part.write_bytes(data[len(data) // 2 :])

    first_diagnostic = diagnose_file(first_part)
    second_diagnostic = diagnose_file(second_part)

    assert first_diagnostic["status"] == "supported_archive"
    assert "split ZIP archive" in first_diagnostic["reason"]
    assert second_diagnostic["status"] == "unsupported"
    assert "auxiliary split archive part" in second_diagnostic["reason"]


def test_ingest_archive_file_routes_split_zip(tmp_path, monkeypatch):
    first_part = tmp_path / "bundle.zip.001"
    first_part.write_bytes(b"part")
    reconstructed = tmp_path / "bundle.zip"
    reconstructed.write_bytes(b"zip")
    calls = {}

    def fake_reconstruct_split_archive(path: Path, target_dir: Path) -> Path:
        calls["first_part"] = path
        calls["target_dir"] = target_dir
        return reconstructed

    def fake_ingest_zip_archive(conn, zip_path: Path, defaults=None, **kwargs):
        calls["zip_path"] = zip_path
        calls["defaults"] = defaults
        calls["limit"] = kwargs.get("limit")
        return [{"status": "indexed", "path": str(zip_path)}]

    monkeypatch.setattr("app.ingest.reconstruct_split_archive", fake_reconstruct_split_archive)
    monkeypatch.setattr("app.ingest.ingest_zip_archive", fake_ingest_zip_archive)

    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        result = ingest_archive_file(conn, first_part, defaults={"source_type": "split"}, limit=5)

    assert result == [{"status": "indexed", "path": str(reconstructed)}]
    assert calls["first_part"] == first_part
    assert calls["zip_path"] == reconstructed
    assert calls["defaults"] == {"source_type": "split"}
    assert calls["limit"] == 5


def test_ingest_document_file_records_locator_fact_span_and_table(tmp_path):
    csv_path = tmp_path / "measurements.csv"
    csv_path.write_text("parameter,value\nтемпература,50 °C\nскорость,0.2 м/с\n", encoding="utf-8")

    with connect(tmp_path / "test.sqlite") as conn:
        create_schema(conn)
        result = ingest_document_file(conn, csv_path, {"source_type": "test", "confidentiality": "internal"})

        assert result["chunks"] == 1
        assert result["tables_found"] == 1
        doc = conn.execute("SELECT locator_type, locator FROM documents").fetchone()
        assert dict(doc) == {"locator_type": "sheet", "locator": "csv"}
        fact = conn.execute(
            """
            SELECT document_id, evidence_locator, evidence_start, evidence_end,
                   extractor_version, validation_status
            FROM facts
            ORDER BY id
            LIMIT 1
            """
        ).fetchone()
        assert fact["document_id"] is not None
        assert fact["evidence_locator"] == "csv"
        assert fact["evidence_start"] is not None
        assert fact["evidence_end"] is not None
        assert fact["extractor_version"] == "dictionary-regex-v2"
        assert fact["validation_status"] == "valid"
        table = conn.execute("SELECT headers_json, rows_json FROM document_tables").fetchone()
        assert "parameter" in table["headers_json"]
        assert "температура" in table["rows_json"]
