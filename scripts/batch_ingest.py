from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import connect, ensure_demo_db, insert_audit
from app.ingest import ingest_folder


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch-ingest a local folder into the R&D knowledge map.")
    parser.add_argument("folder", type=Path, help="Folder to ingest")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of files to route in this run")
    parser.add_argument("--no-resume", action="store_true", help="Do not skip files already indexed in ingest manifest")
    parser.add_argument("--retry-failed", action="store_true", help="Retry manifest rows currently marked failed")
    parser.add_argument("--retry-unsupported", action="store_true", help="Retry manifest rows currently marked skipped_unsupported")
    parser.add_argument("--source-type", default="uploaded_document")
    parser.add_argument("--confidentiality", default="internal")
    parser.add_argument("--reliability-score", type=float, default=0.55)
    parser.add_argument("--geography", default="unknown")
    parser.add_argument("--no-progress", action="store_true", help="Do not print per-file progress to stderr")
    args = parser.parse_args()

    root = args.folder.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Folder not found: {root}")

    ensure_demo_db()
    defaults = {
        "source_type": args.source_type,
        "confidentiality": args.confidentiality,
        "reliability_score": args.reliability_score,
        "geography": args.geography,
    }

    def progress(item: dict) -> None:
        if args.no_progress or str(item.get("status") or "").startswith("already_"):
            return
        payload = {
            "status": item.get("status"),
            "suffix": item.get("suffix"),
            "path": item.get("path"),
            "title": item.get("title"),
            "chunks": item.get("chunks"),
            "facts": item.get("numeric_facts_found"),
            "error": item.get("error"),
        }
        print(json.dumps(payload, ensure_ascii=False), file=sys.stderr, flush=True)

    with connect() as conn:
        results = ingest_folder(
            conn,
            root,
            defaults=defaults,
            limit=args.limit,
            resume=not args.no_resume,
            retry_failed=args.retry_failed,
            retry_unsupported=args.retry_unsupported,
            progress=progress,
            commit_each=True,
        )
        counts = Counter(item.get("status") for item in results)
        insert_audit(
            conn,
            "batch_ingest",
            "admin",
            object_type="folder",
            object_id=str(root),
            details={
                "limit": args.limit,
                "retry_failed": args.retry_failed,
                "retry_unsupported": args.retry_unsupported,
                "counts": dict(counts),
            },
        )

    payload = {
        "folder": str(root),
        "limit": args.limit,
        "retry_failed": args.retry_failed,
        "retry_unsupported": args.retry_unsupported,
        "counts": dict(counts),
        "results": results[:50],
        "truncated_results": len(results) > 50,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
