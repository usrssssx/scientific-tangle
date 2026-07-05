from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.security_review_evidence import security_review_evidence_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate external security review evidence metadata")
    parser.add_argument("path", nargs="?", default=None, help="Evidence JSON path; defaults to RD_KG_SECURITY_REVIEW_EVIDENCE_FILE")
    parser.add_argument("--no-fail", action="store_true", help="Print report without returning non-zero on validation errors")
    args = parser.parse_args()

    report = security_review_evidence_report(args.path)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["ok"] and not args.no_fail:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
