from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import DB_PATH
from app.converters import ConversionCapabilities, detect_conversion_capabilities, split_archive_part_number
from app.ingest import diagnose_file, inventory_folder, rar_volume_number


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def _sample(counter_paths: dict[str, list[str]], limit: int) -> dict[str, list[str]]:
    return {key: paths[:limit] for key, paths in sorted(counter_paths.items())}


def _capabilities_payload(capabilities: ConversionCapabilities) -> dict[str, Any]:
    return {
        "soffice": capabilities.soffice,
        "unrar": capabilities.unrar,
        "tesseract": capabilities.tesseract,
        "ocrmypdf": capabilities.ocrmypdf,
        "seven_zip": capabilities.seven_zip,
        "can_convert_legacy_office": capabilities.can_convert_legacy_office,
        "can_extract_rar": capabilities.can_extract_rar,
        "can_ocr_pdf": capabilities.can_ocr_pdf,
    }


def _is_image_ocr_reason(reason: str) -> bool:
    normalized = reason.lower()
    return "ocr/image" in normalized or "image files require ocr" in normalized or "bmp image" in normalized


def _pending_action(path: Path, diagnostic: dict[str, Any], capabilities: ConversionCapabilities) -> str:
    suffix = diagnostic.get("suffix") or "<none>"
    if _is_image_ocr_reason(str(diagnostic.get("reason") or "")):
        return "requires_image_ocr_pipeline"
    if suffix in {".doc", ".xls", ".ppt"}:
        return "ingest_with_soffice_conversion" if capabilities.can_convert_legacy_office else "install_soffice_for_legacy_office"
    if suffix == ".rar":
        volume_number = rar_volume_number(path)
        if volume_number and volume_number > 1:
            return "skip_auxiliary_rar_volume"
        return "ingest_with_unrar_extraction" if capabilities.can_extract_rar else "install_unrar_for_rar"
    if suffix == ".zip":
        return "ingest_zip_archive"
    if suffix in {".001", ".002"}:
        part_number = split_archive_part_number(path)
        if part_number == 1:
            return "ingest_split_archive_reconstruction"
        if part_number and part_number > 1:
            return "skip_auxiliary_split_archive_part"
        return "implement_split_archive_reconstruction"
    if suffix in {".gif", ".jpg", ".jpeg", ".png", ".tif", ".tiff"}:
        return "requires_image_ocr_pipeline"
    if diagnostic.get("status") == "supported":
        return "continue_batch_ingest"
    if diagnostic.get("status") == "supported_archive":
        return "continue_archive_ingest"
    return "manual_format_triage"


def _manifest_retry_action(row: dict[str, Any], capabilities: ConversionCapabilities) -> str | None:
    status = row.get("status")
    suffix = row.get("suffix") or "<none>"
    error = row.get("error") or ""
    if status == "skipped_unsupported":
        if _is_image_ocr_reason(error):
            return "wait_for_image_ocr_pipeline"
        if suffix in {".doc", ".xls", ".ppt"} and capabilities.can_convert_legacy_office:
            return "retry_unsupported_with_soffice"
        if suffix == ".rar":
            path = Path(row.get("path") or "")
            volume_number = rar_volume_number(path)
            if volume_number and volume_number > 1:
                return "skip_auxiliary_rar_volume"
            if capabilities.can_extract_rar:
                return "retry_unsupported_with_unrar"
        if suffix in {".001", ".002"}:
            path = Path(row.get("path") or "")
            part_number = split_archive_part_number(path)
            if part_number == 1:
                return "retry_split_archive_reconstruction"
            if part_number and part_number > 1:
                return "skip_auxiliary_split_archive_part"
            return "wait_for_split_archive_reconstruction"
        if suffix in {".gif", ".jpg", ".jpeg", ".png", ".tif", ".tiff"}:
            return "wait_for_image_ocr_pipeline"
        return "manual_format_triage"
    if status == "failed" and "No extractable text chunks" in error:
        return "requires_ocr_for_failed_document"
    if status == "failed":
        return "retry_failed_after_error_triage"
    return None


def build_progress_report(root: Path, db_path: Path = DB_PATH, sample_limit: int = 10) -> dict[str, Any]:
    root = root.expanduser().resolve()
    capabilities = detect_conversion_capabilities()
    inventory = inventory_folder(root, largest_limit=5)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        manifest_rows = [_row_dict(row) for row in conn.execute("SELECT * FROM ingest_files").fetchall()]
        source_count = int(conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0])
        document_count = int(conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0])
        fact_count = int(conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0])
    finally:
        conn.close()

    manifest_by_path = {row["path"]: row for row in manifest_rows}
    root_files = [path for path in root.rglob("*") if path.is_file()]
    exact_manifested = [path for path in root_files if str(path) in manifest_by_path]
    unmanifested = [path for path in root_files if str(path) not in manifest_by_path]

    pending_by_status: Counter[str] = Counter()
    pending_by_suffix: Counter[str] = Counter()
    pending_by_domain: Counter[str] = Counter()
    pending_actions: Counter[str] = Counter()
    pending_samples: dict[str, list[str]] = defaultdict(list)
    pending_action_samples: dict[str, list[str]] = defaultdict(list)
    for path in unmanifested:
        diagnostic = diagnose_file(path)
        pending_by_status[diagnostic["status"]] += 1
        pending_by_suffix[diagnostic["suffix"] or "<none>"] += 1
        action = _pending_action(path, diagnostic, capabilities)
        pending_actions[action] += 1
        try:
            rel = path.relative_to(root)
            domain = rel.parts[0] if len(rel.parts) > 1 else "<root>"
        except ValueError:
            domain = "<unknown>"
        pending_by_domain[domain] += 1
        if len(pending_samples[diagnostic["status"]]) < sample_limit:
            pending_samples[diagnostic["status"]].append(str(path))
        if len(pending_action_samples[action]) < sample_limit:
            pending_action_samples[action].append(str(path))

    manifest_status = Counter(row["status"] for row in manifest_rows)
    manifest_suffix_status: Counter[str] = Counter()
    manifest_retry_actions: Counter[str] = Counter()
    failed_by_error: Counter[str] = Counter()
    failed_samples: dict[str, list[str]] = defaultdict(list)
    manifest_retry_samples: dict[str, list[str]] = defaultdict(list)
    for row in manifest_rows:
        manifest_suffix_status[f"{row.get('suffix') or '<none>'}:{row.get('status')}"] += 1
        retry_action = _manifest_retry_action(row, capabilities)
        if retry_action:
            manifest_retry_actions[retry_action] += 1
            if len(manifest_retry_samples[retry_action]) < sample_limit:
                manifest_retry_samples[retry_action].append(row.get("path"))
        if row.get("status") == "failed":
            error = row.get("error") or "<unknown>"
            failed_by_error[error] += 1
            if len(failed_samples[error]) < sample_limit:
                failed_samples[error].append(row.get("path"))

    root_manifest_status = Counter(manifest_by_path[str(path)]["status"] for path in exact_manifested)
    indexed_like = {"indexed", "archive_indexed", "duplicate_skipped"}
    indexed_root_files = sum(1 for path in exact_manifested if manifest_by_path[str(path)]["status"] in indexed_like)
    return {
        "root": str(root),
        "db_path": str(db_path),
        "inventory": {
            "files": inventory["files"],
            "size_bytes": inventory["size_bytes"],
            "by_suffix": inventory["by_suffix"],
            "by_domain": inventory["by_domain"],
            "by_year": inventory["by_year"],
            "size_buckets": inventory["size_buckets"],
            "status_counts": inventory["status_counts"],
        },
        "database_counts": {
            "sources": source_count,
            "documents": document_count,
            "facts": fact_count,
        },
        "manifest": {
            "rows_total": len(manifest_rows),
            "status_counts": dict(manifest_status.most_common()),
            "suffix_status_counts": dict(sorted(manifest_suffix_status.items())),
            "root_exact_files_manifested": len(exact_manifested),
            "root_exact_files_indexed_like": indexed_root_files,
            "root_status_counts": dict(root_manifest_status.most_common()),
            "non_root_manifest_rows": len(manifest_rows) - len(exact_manifested),
        },
        "pending": {
            "files": len(unmanifested),
            "by_status": dict(pending_by_status.most_common()),
            "by_suffix": dict(pending_by_suffix.most_common()),
            "by_domain": dict(pending_by_domain.most_common()),
            "samples": _sample(pending_samples, sample_limit),
        },
        "failures": {
            "by_error": dict(failed_by_error.most_common()),
            "samples": _sample(failed_samples, sample_limit),
        },
        "remediation": {
            "capabilities": _capabilities_payload(capabilities),
            "pending_actions": dict(pending_actions.most_common()),
            "pending_action_samples": _sample(pending_action_samples, sample_limit),
            "manifest_retry_actions": dict(manifest_retry_actions.most_common()),
            "manifest_retry_samples": _sample(manifest_retry_samples, sample_limit),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Report corpus ingest progress from inventory + ingest manifest.")
    parser.add_argument("folder", type=Path, help="Corpus folder")
    parser.add_argument("--db-path", type=Path, default=DB_PATH)
    parser.add_argument("--sample-limit", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = build_progress_report(args.folder, db_path=args.db_path, sample_limit=args.sample_limit)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    print(f"Corpus: {report['root']}")
    print(f"DB: {report['db_path']}")
    print(f"Inventory files: {report['inventory']['files']}")
    print(f"Manifest rows: {report['manifest']['rows_total']}")
    print(f"Root files manifested: {report['manifest']['root_exact_files_manifested']}")
    print(f"Root files indexed-like: {report['manifest']['root_exact_files_indexed_like']}")
    print(f"Pending files: {report['pending']['files']}")
    print("Manifest statuses:")
    for status, count in report["manifest"]["status_counts"].items():
        print(f"  {status}: {count}")
    print("Pending by status:")
    for status, count in report["pending"]["by_status"].items():
        print(f"  {status}: {count}")
    print("Failures:")
    for error, count in report["failures"]["by_error"].items():
        print(f"  {count}: {error}")
    print("Remediation actions:")
    for action, count in report["remediation"]["pending_actions"].items():
        print(f"  pending {action}: {count}")
    for action, count in report["remediation"]["manifest_retry_actions"].items():
        print(f"  manifest {action}: {count}")


if __name__ == "__main__":
    main()
