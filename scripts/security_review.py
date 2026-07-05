from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import DB_PATH
from app.security_review_evidence import SECURITY_REVIEW_EVIDENCE_ENV
from app.security_review import security_review_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run RDKG security review controls")
    parser.add_argument("--profile", choices=["local", "production"], default="local")
    parser.add_argument("--database", type=Path, default=DB_PATH)
    parser.add_argument("--evidence-file", type=Path, help="External security review evidence metadata JSON")
    parser.add_argument("--no-fail", action="store_true", help="Print report without returning non-zero on failed controls")
    args = parser.parse_args()

    if args.evidence_file:
        os.environ[SECURITY_REVIEW_EVIDENCE_ENV] = str(args.evidence_file)
    report = security_review_report(profile=args.profile, db_path=args.database)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["overall_status"] == "fail" and not args.no_fail:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
