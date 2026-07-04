from __future__ import annotations

import hashlib
import re
import shutil
import zipfile
from collections.abc import Callable
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .config import UPLOAD_DIR
from .converters import (
    detect_conversion_capabilities,
    extract_rar_archive,
    has_consecutive_split_parts,
    reconstruct_split_archive,
    split_archive_base_name,
    split_archive_part_number,
)
from .db import (
    ensure_ingest_manifest_schema,
    insert_document_chunk,
    insert_document_table,
    insert_edge,
    insert_fact,
    insert_source,
    upsert_entity,
    upsert_ingest_file,
)
from .extract import (
    EXTRACTOR_VERSION,
    chunk_text_with_locations,
    detect_language,
    extract_entities,
    extract_numeric_conditions,
    extract_table_rows,
    load_domain_terms,
    read_document_text,
    validate_numeric_hit,
)

SUPPORTED_SUFFIXES = {".md", ".txt", ".pdf", ".docx", ".docm", ".pptx", ".xlsx", ".csv", ".json"}
LEGACY_OFFICE_SUFFIXES = {".doc", ".xls", ".ppt"}
ARCHIVE_SUFFIXES = {".zip", ".rar", ".001"}
SPLIT_ARCHIVE_SUFFIXES = {".001", ".002"}
KNOWN_UNSUPPORTED_SUFFIXES = {
    ".doc": "legacy DOC requires conversion to DOCX/PDF before parsing",
    ".xls": "legacy XLS requires xlrd or conversion to XLSX/CSV",
    ".ppt": "legacy PPT requires conversion to PPTX/PDF before parsing",
    ".rar": "RAR archives require an external extractor",
    ".001": "split archive part requires archive reconstruction before ingest",
    ".002": "split archive part requires archive reconstruction before ingest",
    ".gif": "image files require OCR/image extraction",
    "": "file has no extension and cannot be routed safely",
}
RESUME_INDEXED_STATUSES = {"indexed", "archive_indexed", "duplicate_skipped"}
RAR_VOLUME_RE = re.compile(r"\.part(?P<number>\d+)\.rar$", flags=re.IGNORECASE)
IMAGE_MAGIC_SIGNATURES = (
    (b"BM", "BMP image files require OCR/image extraction"),
    (b"GIF87a", "image files require OCR/image extraction"),
    (b"GIF89a", "image files require OCR/image extraction"),
    (b"\x89PNG\r\n\x1a\n", "image files require OCR/image extraction"),
    (b"\xff\xd8\xff", "image files require OCR/image extraction"),
    (b"II*\x00", "image files require OCR/image extraction"),
    (b"MM\x00*", "image files require OCR/image extraction"),
)


def checksum_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def rar_volume_number(path: Path) -> int | None:
    match = RAR_VOLUME_RE.search(path.name)
    if not match:
        return None
    return int(match.group("number"))


def image_magic_reason(path: Path) -> str | None:
    try:
        header = path.read_bytes()[:16]
    except OSError:
        return None
    for magic, reason in IMAGE_MAGIC_SIGNATURES:
        if header.startswith(magic):
            return reason
    return None


def diagnose_file(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    size = path.stat().st_size
    image_reason = image_magic_reason(path)
    if image_reason:
        return {"path": str(path), "suffix": suffix, "size_bytes": size, "status": "unsupported", "reason": image_reason}
    if suffix in SUPPORTED_SUFFIXES:
        return {"path": str(path), "suffix": suffix, "size_bytes": size, "status": "supported", "reason": None}
    capabilities = detect_conversion_capabilities()
    if suffix in LEGACY_OFFICE_SUFFIXES:
        if capabilities.can_convert_legacy_office:
            return {
                "path": str(path),
                "suffix": suffix,
                "size_bytes": size,
                "status": "supported",
                "reason": f"legacy Office will be converted with {Path(capabilities.soffice or 'soffice').name}",
            }
        return {
            "path": str(path),
            "suffix": suffix,
            "size_bytes": size,
            "status": "unsupported",
            "reason": KNOWN_UNSUPPORTED_SUFFIXES.get(suffix, f"unsupported format: {suffix or '<none>'}"),
        }
    if suffix == ".zip":
        return {
            "path": str(path),
            "suffix": suffix,
            "size_bytes": size,
            "status": "supported_archive",
            "reason": None,
        }
    if suffix == ".rar":
        volume_number = rar_volume_number(path)
        if volume_number and volume_number > 1:
            return {
                "path": str(path),
                "suffix": suffix,
                "size_bytes": size,
                "status": "unsupported",
                "reason": "auxiliary multipart RAR volume; ingest the matching .part1.rar instead",
            }
        if capabilities.can_extract_rar:
            archive_kind = "multipart RAR archive" if volume_number == 1 else "RAR archive"
            return {
                "path": str(path),
                "suffix": suffix,
                "size_bytes": size,
                "status": "supported_archive",
                "reason": f"{archive_kind} will be extracted with {Path(capabilities.unrar or 'unrar').name}",
            }
        return {
            "path": str(path),
            "suffix": suffix,
            "size_bytes": size,
            "status": "unsupported",
            "reason": KNOWN_UNSUPPORTED_SUFFIXES[suffix],
        }
    if suffix in SPLIT_ARCHIVE_SUFFIXES:
        part_number = split_archive_part_number(path)
        if part_number == 1:
            base_name = split_archive_base_name(path)
            base_suffix = Path(base_name or "").suffix.lower()
            if base_suffix == ".zip" and has_consecutive_split_parts(path):
                part_count = len([part for part in path.parent.iterdir() if split_archive_base_name(part) == base_name])
                return {
                    "path": str(path),
                    "suffix": suffix,
                    "size_bytes": size,
                    "status": "supported_archive",
                    "reason": f"split ZIP archive will be reconstructed from {part_count} parts",
                }
            return {
                "path": str(path),
                "suffix": suffix,
                "size_bytes": size,
                "status": "unsupported",
                "reason": "split archive first part is missing later parts or has unsupported base format",
            }
        if part_number and part_number > 1:
            return {
                "path": str(path),
                "suffix": suffix,
                "size_bytes": size,
                "status": "unsupported",
                "reason": "auxiliary split archive part; ingest the matching .001 instead",
            }
        reason = KNOWN_UNSUPPORTED_SUFFIXES[suffix]
        if capabilities.seven_zip:
            reason = f"{reason}; 7z detected but split archive reconstruction is not implemented yet"
        return {"path": str(path), "suffix": suffix, "size_bytes": size, "status": "unsupported", "reason": reason}
    return {
        "path": str(path),
        "suffix": suffix,
        "size_bytes": size,
        "status": "unsupported",
        "reason": KNOWN_UNSUPPORTED_SUFFIXES.get(suffix, f"unsupported format: {suffix or '<none>'}"),
    }


def infer_metadata_from_path(path: Path, defaults: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = dict(defaults or {})
    parts = [p.lower() for p in path.parts]
    stem = path.stem
    metadata.setdefault("title", stem)
    if "доклады" in parts:
        metadata.setdefault("source_type", "presentation_or_report")
    elif "обзоры" in parts:
        metadata.setdefault("source_type", "literature_review")
    elif "журналы" in parts:
        metadata.setdefault("source_type", "journal")
    elif "материалы конференций" in parts or "материалы конференций" in parts:
        metadata.setdefault("source_type", "conference_material")
    else:
        metadata.setdefault("source_type", "uploaded_document")
    metadata.setdefault("confidentiality", "internal")
    metadata.setdefault("reliability_score", 0.55)
    metadata.setdefault("geography", "unknown")
    year_match = re.search(r"(20\d{2}|19\d{2})", " ".join(path.parts))
    if year_match and "year" not in metadata:
        metadata["year"] = int(year_match.group(1))
    return metadata


def _language_hint_from_path(path: Path) -> str:
    text = " ".join(path.parts)
    has_cyrillic = bool(re.search(r"[а-яА-ЯёЁ]", text))
    has_latin = bool(re.search(r"[A-Za-z]", text))
    if has_cyrillic and has_latin:
        return "mixed"
    if has_cyrillic:
        return "ru"
    if has_latin:
        return "en"
    return "unknown"


def _size_bucket(size_bytes: int) -> str:
    mb = size_bytes / (1024 * 1024)
    if mb < 1:
        return "<1MB"
    if mb < 10:
        return "1-10MB"
    if mb < 50:
        return "10-50MB"
    if mb < 100:
        return "50-100MB"
    return ">=100MB"


def _duplicate_groups(groups: dict[tuple[Any, ...], list[Path]], limit: int = 20) -> list[dict[str, Any]]:
    duplicates = [(key, paths) for key, paths in groups.items() if len(paths) > 1]
    duplicates.sort(key=lambda item: (len(item[1]), item[0]), reverse=True)
    result = []
    for key, paths in duplicates[:limit]:
        result.append(
            {
                "key": list(key),
                "count": len(paths),
                "paths": [str(path) for path in paths[:10]],
                "truncated_paths": len(paths) > 10,
            }
        )
    return result


def inventory_folder(
    root: Path,
    include_checksums: bool = False,
    max_checksum_bytes: int | None = None,
    largest_limit: int = 20,
) -> dict[str, Any]:
    files = [path for path in root.rglob("*") if path.is_file()]
    by_suffix = Counter((path.suffix.lower() or "<none>") for path in files)
    diagnostics = [diagnose_file(path) for path in files]
    status_counts = Counter(item["status"] for item in diagnostics)
    unsupported_reasons = Counter(
        item["reason"] for item in diagnostics if item["status"] == "unsupported" and item["reason"]
    )
    by_domain: Counter[str] = Counter()
    by_year: Counter[str] = Counter()
    by_language_hint: Counter[str] = Counter()
    size_buckets: Counter[str] = Counter()
    name_size_groups: dict[tuple[Any, ...], list[Path]] = defaultdict(list)
    checksum_groups: dict[tuple[Any, ...], list[Path]] = defaultdict(list)
    checksum_skipped = 0

    for path in files:
        try:
            relative = path.relative_to(root)
            domain = relative.parts[0] if len(relative.parts) > 1 else "<root>"
        except ValueError:
            domain = "<unknown>"
        by_domain[domain] += 1
        by_language_hint[_language_hint_from_path(path)] += 1
        size_buckets[_size_bucket(path.stat().st_size)] += 1
        name_size_groups[(path.name.lower(), path.stat().st_size)].append(path)
        for year in sorted(set(re.findall(r"(?:19|20)\d{2}", " ".join(path.parts)))):
            by_year[year] += 1
        if include_checksums:
            if max_checksum_bytes is not None and path.stat().st_size > max_checksum_bytes:
                checksum_skipped += 1
                continue
            checksum_groups[(checksum_file(path), path.stat().st_size)].append(path)

    largest_files = sorted(files, key=lambda path: path.stat().st_size, reverse=True)[:largest_limit]
    return {
        "root": str(root),
        "files": len(files),
        "dirs": sum(1 for path in root.rglob("*") if path.is_dir()),
        "size_bytes": sum(path.stat().st_size for path in files),
        "by_suffix": dict(by_suffix.most_common()),
        "by_domain": dict(by_domain.most_common()),
        "by_year": dict(sorted(by_year.items())),
        "by_language_hint": dict(by_language_hint.most_common()),
        "size_buckets": dict(size_buckets.most_common()),
        "status_counts": dict(status_counts.most_common()),
        "unsupported_reasons": dict(unsupported_reasons.most_common()),
        "largest_files": [
            {
                "path": str(path),
                "suffix": path.suffix.lower() or "<none>",
                "size_bytes": path.stat().st_size,
                "diagnostic_status": diagnose_file(path)["status"],
            }
            for path in largest_files
        ],
        "duplicate_name_size_groups": _duplicate_groups(name_size_groups),
        "checksum_duplicates": _duplicate_groups(checksum_groups) if include_checksums else [],
        "checksum_skipped_large_files": checksum_skipped,
        "checksum_mode": {
            "enabled": include_checksums,
            "max_checksum_bytes": max_checksum_bytes,
        },
    }


def ingest_document_file(conn, path: Path, defaults: dict[str, Any] | None = None) -> dict[str, Any]:
    defaults = defaults or {}
    meta, text = read_document_text(path)
    metadata = infer_metadata_from_path(path, defaults)
    metadata.update({k: v for k, v in meta.items() if v is not None})
    metadata.setdefault("title", path.stem)
    metadata.setdefault("source_type", "uploaded_document")
    metadata.setdefault("language", detect_language(text))
    metadata.setdefault("geography", "unknown")
    metadata.setdefault("reliability_score", 0.55)
    metadata.setdefault("confidentiality", "internal")
    if "checksum_sha256" not in metadata:
        metadata["checksum_sha256"] = checksum_file(path)
    chunks = chunk_text_with_locations(text)
    if not chunks:
        raise RuntimeError("No extractable text chunks; OCR or format-specific parser is required")
    source_id = insert_source(conn, metadata, path=str(path), abstract=text[:500])
    source_entity_id = upsert_entity(conn, "Publication", metadata["title"], metadata["title"], [])

    terms = load_domain_terms()
    total_entities = 0
    total_facts = 0
    total_tables = 0
    for chunk_no, chunk_info in enumerate(chunks):
        chunk = chunk_info.text
        document_id = insert_document_chunk(
            conn,
            source_id,
            chunk_no,
            chunk,
            locator_type=chunk_info.locator_type,
            locator=chunk_info.locator,
            start_char=chunk_info.start_char,
            end_char=chunk_info.end_char,
            metadata=chunk_info.metadata or {},
        )
        table = extract_table_rows(chunk)
        if table:
            headers, rows = table
            insert_document_table(
                conn,
                source_id=source_id,
                document_id=document_id,
                locator=chunk_info.locator,
                headers=headers,
                rows=rows,
                table_type="detected_pipe_table",
                confidence=float(metadata["reliability_score"]),
            )
            total_tables += 1
        entity_hits = extract_entities(chunk, terms)
        total_entities += len(entity_hits)
        for hit in entity_hits:
            ent_id = upsert_entity(conn, hit.type, hit.canonical, hit.canonical, [])
            insert_edge(conn, source_id, source_entity_id, "describes", ent_id, float(metadata["reliability_score"]), hit.alias)
        process_hits = [h for h in entity_hits if h.type == "Process"]
        material_hits = [h for h in entity_hits if h.type == "Material"]
        equipment_hits = [h for h in entity_hits if h.type == "Equipment"]
        for p in process_hits:
            p_id = upsert_entity(conn, "Process", p.canonical, p.canonical, [])
            for m in material_hits:
                m_id = upsert_entity(conn, "Material", m.canonical, m.canonical, [])
                insert_edge(conn, source_id, p_id, "uses_material", m_id, float(metadata["reliability_score"]), chunk[:300])
            for e in equipment_hits:
                e_id = upsert_entity(conn, "Equipment", e.canonical, e.canonical, [])
                insert_edge(conn, source_id, p_id, "uses_equipment", e_id, float(metadata["reliability_score"]), chunk[:300])
        for nh in extract_numeric_conditions(chunk, terms):
            subject_id = source_entity_id
            local_process = [h for h in extract_entities(nh.evidence, terms) if h.type == "Process"]
            if local_process:
                subject_id = upsert_entity(conn, "Process", local_process[0].canonical, local_process[0].canonical, [])
            validation_status, validation_warnings = validate_numeric_hit(nh)
            extraction_confidence = float(metadata["reliability_score"])
            if validation_status != "valid":
                extraction_confidence = max(0.1, extraction_confidence - 0.25)
            evidence_start = None
            evidence_end = None
            if chunk_info.start_char is not None:
                evidence_start = chunk_info.start_char + nh.start
                evidence_end = chunk_info.start_char + nh.end
            insert_fact(
                conn,
                source_id=source_id,
                subject_id=subject_id,
                predicate="has_numeric_condition",
                property_=nh.property,
                comparator=nh.comparator,
                numeric_value=nh.value,
                min_value=nh.min_value,
                max_value=nh.max_value,
                unit=nh.unit,
                confidence=float(metadata["reliability_score"]),
                extraction_confidence=extraction_confidence,
                validation_status=validation_status,
                validation_warnings=validation_warnings,
                document_id=document_id,
                evidence=nh.evidence[:800],
                evidence_locator=chunk_info.locator,
                evidence_start=evidence_start,
                evidence_end=evidence_end,
                extractor_version=EXTRACTOR_VERSION,
            )
            total_facts += 1
    return {
        "source_id": source_id,
        "title": metadata["title"],
        "chunks": len(chunks),
        "entities_found": total_entities,
        "numeric_facts_found": total_facts,
        "tables_found": total_tables,
        "checksum_sha256": metadata["checksum_sha256"],
    }


def ingest_folder(
    conn,
    root: Path,
    defaults: dict[str, Any] | None = None,
    limit: int | None = None,
    resume: bool = True,
    retry_failed: bool = False,
    retry_unsupported: bool = False,
    progress: Callable[[dict[str, Any]], None] | None = None,
    commit_each: bool = False,
) -> list[dict[str, Any]]:
    results = []
    processed = 0
    ensure_ingest_manifest_schema(conn)

    def record(item: dict[str, Any], durable: bool = False) -> None:
        results.append(item)
        if progress:
            progress(item)
        if durable and commit_each:
            conn.commit()

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        diagnostic = diagnose_file(path)
        suffix = diagnostic["suffix"]
        size = diagnostic["size_bytes"]
        if resume:
            row = conn.execute("SELECT status, error, source_id FROM ingest_files WHERE path = ?", (str(path),)).fetchone()
            if row and row["status"] in RESUME_INDEXED_STATUSES:
                item = {**diagnostic, "status": "already_indexed", "ingested": False}
                record(item)
                continue
            if row and row["status"] == "skipped_unsupported" and not retry_unsupported:
                item = {**diagnostic, "status": "already_unsupported", "error": row["error"], "ingested": False}
                record(item)
                continue
            if row and row["status"] == "failed" and not retry_failed:
                item = {**diagnostic, "status": "already_failed", "error": row["error"], "ingested": False}
                record(item)
                continue
        if limit is not None and processed >= limit:
            break
        if diagnostic["status"] == "supported_archive":
            remaining = None if limit is None else max(0, limit - processed)
            try:
                checksum = checksum_file(path)
                upsert_ingest_file(conn, str(path), suffix, size, "processing", checksum=checksum, mark_started=True)
                archive_results = ingest_archive_file(
                    conn,
                    path,
                    defaults=defaults,
                    limit=remaining,
                    resume=resume,
                    retry_failed=retry_failed,
                    retry_unsupported=retry_unsupported,
                    progress=progress,
                    commit_each=commit_each,
                )
                status_counts = Counter(item.get("status") for item in archive_results)
                result = {
                    **diagnostic,
                    "status": "archive_indexed",
                    "ingested": True,
                    "child_count": len(archive_results),
                    "child_status_counts": dict(status_counts),
                }
                upsert_ingest_file(conn, str(path), suffix, size, "archive_indexed", checksum=checksum, result=result, mark_finished=True)
                record(result, durable=True)
            except Exception as exc:
                item = {**diagnostic, "status": "failed", "error": str(exc), "ingested": False}
                upsert_ingest_file(conn, str(path), suffix, size, "failed", error=str(exc), result=item, mark_finished=True)
                record(item, durable=True)
            processed += 1
            continue
        if diagnostic["status"] != "supported":
            item = {**diagnostic, "status": "skipped_unsupported", "ingested": False}
            upsert_ingest_file(conn, str(path), suffix, size, "skipped_unsupported", error=diagnostic["reason"], result=item, mark_finished=True)
            record(item, durable=True)
            processed += 1
            continue
        try:
            checksum = checksum_file(path)
            if resume:
                duplicate = conn.execute(
                    """
                    SELECT path, source_id
                    FROM ingest_files
                    WHERE checksum = ?
                      AND path <> ?
                      AND status IN ('indexed', 'archive_indexed')
                    ORDER BY id
                    LIMIT 1
                    """,
                    (checksum, str(path)),
                ).fetchone()
                if duplicate is not None:
                    item = {
                        **diagnostic,
                        "status": "duplicate_skipped",
                        "ingested": False,
                        "duplicate_of": duplicate["path"],
                        "source_id": duplicate["source_id"],
                        "checksum_sha256": checksum,
                    }
                    upsert_ingest_file(
                        conn,
                        str(path),
                        suffix,
                        size,
                        "duplicate_skipped",
                        checksum=checksum,
                        source_id=duplicate["source_id"],
                        result=item,
                        mark_finished=True,
                    )
                    record(item, durable=True)
                    processed += 1
                    continue
            upsert_ingest_file(conn, str(path), suffix, size, "processing", checksum=checksum, mark_started=True)
            result = ingest_document_file(conn, path, {**(defaults or {}), "checksum_sha256": checksum})
            upsert_ingest_file(
                conn,
                str(path),
                suffix,
                size,
                "indexed",
                checksum=checksum,
                source_id=result.get("source_id"),
                result=result,
                mark_finished=True,
            )
            record({"path": str(path), "suffix": suffix, "size_bytes": size, "status": "indexed", "ingested": True, **result}, durable=True)
        except Exception as exc:
            item = {**diagnostic, "status": "failed", "error": str(exc), "ingested": False}
            upsert_ingest_file(conn, str(path), suffix, size, "failed", error=str(exc), result=item, mark_finished=True)
            record(item, durable=True)
        processed += 1
    return results


def _safe_extract_zip(zip_path: Path, target_dir: Path) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    extract_root = target_dir / zip_path.stem
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            member_path = extract_root / member.filename
            if not str(member_path.resolve()).startswith(str(extract_root.resolve())):
                raise RuntimeError(f"Небезопасный путь в архиве: {member.filename}")
        zf.extractall(extract_root)
    return extract_root


def ingest_zip_archive(
    conn,
    zip_path: Path,
    defaults: dict[str, Any] | None = None,
    limit: int | None = None,
    resume: bool = True,
    retry_failed: bool = False,
    retry_unsupported: bool = False,
    progress: Callable[[dict[str, Any]], None] | None = None,
    commit_each: bool = False,
) -> list[dict[str, Any]]:
    extract_root = _safe_extract_zip(zip_path, UPLOAD_DIR / "extracted")
    return ingest_folder(
        conn,
        extract_root,
        defaults,
        limit=limit,
        resume=resume,
        retry_failed=retry_failed,
        retry_unsupported=retry_unsupported,
        progress=progress,
        commit_each=commit_each,
    )


def ingest_rar_archive(
    conn,
    rar_path: Path,
    defaults: dict[str, Any] | None = None,
    limit: int | None = None,
    resume: bool = True,
    retry_failed: bool = False,
    retry_unsupported: bool = False,
    progress: Callable[[dict[str, Any]], None] | None = None,
    commit_each: bool = False,
) -> list[dict[str, Any]]:
    extract_root = extract_rar_archive(rar_path, UPLOAD_DIR / "extracted")
    return ingest_folder(
        conn,
        extract_root,
        defaults,
        limit=limit,
        resume=resume,
        retry_failed=retry_failed,
        retry_unsupported=retry_unsupported,
        progress=progress,
        commit_each=commit_each,
    )


def ingest_split_archive(
    conn,
    first_part: Path,
    defaults: dict[str, Any] | None = None,
    limit: int | None = None,
    resume: bool = True,
    retry_failed: bool = False,
    retry_unsupported: bool = False,
    progress: Callable[[dict[str, Any]], None] | None = None,
    commit_each: bool = False,
) -> list[dict[str, Any]]:
    reconstructed = reconstruct_split_archive(first_part, UPLOAD_DIR / "reconstructed")
    if reconstructed.suffix.lower() == ".zip":
        return ingest_zip_archive(
            conn,
            reconstructed,
            defaults=defaults,
            limit=limit,
            resume=resume,
            retry_failed=retry_failed,
            retry_unsupported=retry_unsupported,
            progress=progress,
            commit_each=commit_each,
        )
    raise RuntimeError(f"Reconstructed archive format {reconstructed.suffix} is not supported")


def ingest_archive_file(
    conn,
    archive_path: Path,
    defaults: dict[str, Any] | None = None,
    limit: int | None = None,
    resume: bool = True,
    retry_failed: bool = False,
    retry_unsupported: bool = False,
    progress: Callable[[dict[str, Any]], None] | None = None,
    commit_each: bool = False,
) -> list[dict[str, Any]]:
    suffix = archive_path.suffix.lower()
    if suffix == ".zip":
        return ingest_zip_archive(
            conn,
            archive_path,
            defaults=defaults,
            limit=limit,
            resume=resume,
            retry_failed=retry_failed,
            retry_unsupported=retry_unsupported,
            progress=progress,
            commit_each=commit_each,
        )
    if suffix == ".rar":
        return ingest_rar_archive(
            conn,
            archive_path,
            defaults=defaults,
            limit=limit,
            resume=resume,
            retry_failed=retry_failed,
            retry_unsupported=retry_unsupported,
            progress=progress,
            commit_each=commit_each,
        )
    if suffix == ".001":
        return ingest_split_archive(
            conn,
            archive_path,
            defaults=defaults,
            limit=limit,
            resume=resume,
            retry_failed=retry_failed,
            retry_unsupported=retry_unsupported,
            progress=progress,
            commit_each=commit_each,
        )
    raise RuntimeError(f"Archive format {suffix} is not supported")
