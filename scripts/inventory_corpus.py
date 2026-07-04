from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ingest import inventory_folder


def main() -> None:
    parser = argparse.ArgumentParser(description="Inventory a local R&D corpus without parsing file contents.")
    parser.add_argument("folder", type=Path, help="Corpus folder to inspect")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument("--checksums", action="store_true", help="Compute SHA-256 checksums for duplicate detection")
    parser.add_argument("--max-checksum-mb", type=float, default=None, help="Only checksum files up to this size in MB")
    parser.add_argument("--largest-limit", type=int, default=20, help="Number of largest files to include")
    args = parser.parse_args()

    root = args.folder.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Folder not found: {root}")

    max_checksum_bytes = None
    if args.max_checksum_mb is not None:
        max_checksum_bytes = int(args.max_checksum_mb * 1024 * 1024)
    report = inventory_folder(
        root,
        include_checksums=args.checksums,
        max_checksum_bytes=max_checksum_bytes,
        largest_limit=args.largest_limit,
    )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    print(f"Corpus: {report['root']}")
    print(f"Files: {report['files']}")
    print(f"Dirs: {report['dirs']}")
    print(f"Size bytes: {report['size_bytes']}")
    print("By suffix:")
    for suffix, count in report["by_suffix"].items():
        print(f"  {suffix}: {count}")
    print("By domain folder:")
    for domain, count in report["by_domain"].items():
        print(f"  {domain}: {count}")
    print("By year hint:")
    for year, count in report["by_year"].items():
        print(f"  {year}: {count}")
    print("By language hint:")
    for language, count in report["by_language_hint"].items():
        print(f"  {language}: {count}")
    print("Size buckets:")
    for bucket, count in report["size_buckets"].items():
        print(f"  {bucket}: {count}")
    print("Statuses:")
    for status, count in report["status_counts"].items():
        print(f"  {status}: {count}")
    print("Unsupported / routed reasons:")
    for reason, count in report["unsupported_reasons"].items():
        print(f"  {count}: {reason}")
    print("Largest files:")
    for item in report["largest_files"]:
        print(f"  {item['size_bytes']}: {item['path']} ({item['diagnostic_status']})")
    print("Duplicate candidates by name+size:")
    for item in report["duplicate_name_size_groups"]:
        print(f"  {item['count']}x {item['key']}")
    if args.checksums:
        print("Checksum duplicates:")
        for item in report["checksum_duplicates"]:
            print(f"  {item['count']}x {item['key']}")
        if report["checksum_skipped_large_files"]:
            print(f"Checksum skipped large files: {report['checksum_skipped_large_files']}")


if __name__ == "__main__":
    main()
