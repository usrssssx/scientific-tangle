from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import DB_PATH
from app.db import connect
from app.directory_sync import (
    apply_directory_sync,
    directory_sync_config_report,
    load_directory_payload_from_config,
    load_directory_sync_config,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync directory users/groups from AD/LDAP or JSON into local directory tables")
    parser.add_argument("--config", type=Path, required=True, help="Directory sync config JSON")
    parser.add_argument("--database", type=Path, default=DB_PATH)
    parser.add_argument("--input", type=Path, help="JSON source payload; useful when config source=json")
    parser.add_argument("--apply", action="store_true", help="Apply changes. Default is dry-run.")
    parser.add_argument("--validate-only", action="store_true", help="Validate config and exit without reading source directory")
    parser.add_argument("--deactivate-missing", action="store_true", help="Deactivate local users missing from source")
    parser.add_argument("--delete-missing-groups", action="store_true", help="Delete local groups missing from source")
    parser.add_argument("--actor", default="directory-sync")
    args = parser.parse_args()

    report = directory_sync_config_report(args.config)
    if not report["ok"]:
        print(json.dumps({"ok": False, "config": report}, ensure_ascii=False, indent=2))
        raise SystemExit(1)
    if args.validate_only:
        print(json.dumps({"ok": True, "config": report}, ensure_ascii=False, indent=2))
        return
    config = load_directory_sync_config(args.config)
    payload = load_directory_payload_from_config(config, input_path=args.input)
    deactivate_missing = args.deactivate_missing or bool(config.get("deactivate_missing"))
    delete_missing_groups = args.delete_missing_groups or bool(config.get("delete_missing_groups"))
    with connect(args.database) as conn:
        stats = apply_directory_sync(
            conn,
            payload,
            dry_run=not args.apply,
            deactivate_missing=deactivate_missing,
            delete_missing_groups=delete_missing_groups,
            actor=args.actor,
            actor_role="admin",
        )
    print(json.dumps({"ok": True, "config": report, "stats": stats}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
