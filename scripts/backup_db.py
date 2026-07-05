from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import DB_PATH

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BACKUP_DIR = PROJECT_ROOT / "data" / "backups"
DEFAULT_KEY_ENV = "RD_KG_BACKUP_KEY"
ENCRYPTED_BACKUP_MAGIC = b"RDKGBAK1\n"
ENCRYPTED_BACKUP_CHUNK_SIZE = 1024 * 1024
DEFAULT_DRILL_MIN_COUNTS = {"sources": 1, "documents": 1, "facts": 1}
DEFAULT_BACKUP_PLAN = {
    "backup_dir": "data/backups",
    "encrypted": True,
    "key_env": DEFAULT_KEY_ENV,
    "keep_plaintext": False,
    "offsite_dir": None,
    "retention": {
        "pattern": "rd_knowledge_*.sqlite*",
        "keep_latest": 14,
        "max_age_days": 30,
    },
    "offsite_retention": {
        "pattern": "rd_knowledge_*.sqlite*",
        "keep_latest": 30,
        "max_age_days": 90,
    },
    "restore_drill": {
        "enabled": True,
        "require_embeddings": False,
        "min_counts": DEFAULT_DRILL_MIN_COUNTS,
    },
}


def sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def write_checksum(path: Path, checksum: str) -> Path:
    checksum_path = path.with_suffix(path.suffix + ".sha256")
    checksum_path.write_text(f"{checksum}  {path.name}\n", encoding="utf-8")
    return checksum_path


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _backup_artifact_paths(payload: dict) -> list[Path]:
    paths: list[Path] = []
    for key in ("destination", "checksum_file", "manifest_file"):
        value = payload.get(key)
        if value:
            path = Path(str(value))
            if path.exists():
                paths.append(path)
    return paths


def copy_backup_artifacts(payload: dict, offsite_dir: Path | str) -> dict:
    destination = Path(offsite_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    copied = []
    for artifact in _backup_artifact_paths(payload):
        target = destination / artifact.name
        shutil.copy2(artifact, target)
        copied.append(
            {
                "source": str(artifact),
                "destination": str(target),
                "size_bytes": target.stat().st_size,
                "sha256": sha256_file(target),
            }
        )
    return {"destination": str(destination), "copied": copied}


def _resolve_plan_path(value: str | Path | None) -> Path | None:
    if value is None or str(value).strip() == "":
        return None
    path = Path(str(value)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (PROJECT_ROOT / path).resolve()


def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key == "min_counts":
            result[key] = value
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_backup_plan(config_path: Path | str | None = None) -> dict:
    if config_path is None:
        return copy.deepcopy(DEFAULT_BACKUP_PLAN)
    path = Path(config_path).expanduser().resolve()
    if not path.exists():
        raise SystemExit(f"Backup plan config not found: {path}")
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Backup plan config is not valid JSON: {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise SystemExit("Backup plan config must be a JSON object.")
    return _deep_merge(DEFAULT_BACKUP_PLAN, loaded)


def _backup_primary_artifacts(directory: Path, pattern: str) -> list[Path]:
    if not directory.exists():
        return []
    primaries = []
    for path in directory.glob(pattern):
        if not path.is_file():
            continue
        name = path.name
        if name.endswith(".sha256") or name.endswith(".manifest.json"):
            continue
        if name.endswith(".sqlite") or name.endswith(".sqlite.enc"):
            primaries.append(path)
    return sorted(primaries, key=lambda item: (item.stat().st_mtime, item.name), reverse=True)


def _artifact_group(primary: Path) -> list[Path]:
    candidates = [
        primary,
        primary.with_suffix(primary.suffix + ".sha256"),
    ]
    if primary.name.endswith(".sqlite.enc"):
        candidates.append(primary.with_suffix(primary.suffix + ".manifest.json"))
    return [path for path in candidates if path.exists()]


def prune_backup_artifacts(
    directory: Path | str,
    pattern: str = "rd_knowledge_*.sqlite*",
    keep_latest: int | None = None,
    max_age_days: int | None = None,
    dry_run: bool = False,
) -> dict:
    target_dir = Path(directory).expanduser().resolve()
    if keep_latest is not None and int(keep_latest) < 0:
        raise SystemExit("Retention keep_latest must be >= 0.")
    if max_age_days is not None and int(max_age_days) < 0:
        raise SystemExit("Retention max_age_days must be >= 0.")
    primaries = _backup_primary_artifacts(target_dir, pattern)
    keep_latest = None if keep_latest is None else int(keep_latest)
    max_age_days = None if max_age_days is None else int(max_age_days)
    cutoff_ts = None
    if max_age_days is not None:
        cutoff_ts = datetime.now(timezone.utc).timestamp() - max_age_days * 24 * 60 * 60

    deleted: list[dict] = []
    kept: list[str] = []
    for index, primary in enumerate(primaries):
        protected_by_latest = keep_latest is not None and index < keep_latest
        reason = None
        if not protected_by_latest and cutoff_ts is not None and primary.stat().st_mtime < cutoff_ts:
            reason = f"older_than_{max_age_days}_days"
        elif keep_latest is not None and not protected_by_latest and cutoff_ts is None:
            reason = f"beyond_latest_{keep_latest}"

        if reason is None:
            kept.append(str(primary))
            continue

        for artifact in _artifact_group(primary):
            deleted.append(
                {
                    "path": str(artifact),
                    "reason": reason,
                    "size_bytes": artifact.stat().st_size,
                }
            )
            if not dry_run:
                artifact.unlink(missing_ok=True)

    return {
        "action": "retention",
        "directory": str(target_dir),
        "pattern": pattern,
        "keep_latest": keep_latest,
        "max_age_days": max_age_days,
        "dry_run": dry_run,
        "primary_count": len(primaries),
        "kept": kept,
        "deleted": [] if dry_run else deleted,
        "would_delete": deleted if dry_run else [],
    }


def generate_backup_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def _backup_key(key: str | None = None, key_env: str = DEFAULT_KEY_ENV) -> bytes:
    key_value = key or os.getenv(key_env)
    if not key_value:
        raise SystemExit(f"Encrypted backup requires a base64 key in --key or ${key_env}. Generate one with --generate-key.")
    try:
        raw = base64.urlsafe_b64decode(key_value.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - normalize CLI error text
        raise SystemExit("Backup encryption key must be urlsafe base64.") from exc
    if len(raw) not in {16, 24, 32}:
        raise SystemExit("Backup encryption key must decode to 16, 24, or 32 bytes.")
    return raw


def encrypt_backup_file(source: Path, destination: Path | None = None, key: str | None = None, key_env: str = DEFAULT_KEY_ENV) -> dict:
    source = source.expanduser().resolve()
    if not source.exists():
        raise SystemExit(f"Backup not found: {source}")
    destination = (destination or source.with_suffix(source.suffix + ".enc")).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    aesgcm = AESGCM(_backup_key(key, key_env))
    nonce_prefix = os.urandom(8)
    header = ENCRYPTED_BACKUP_MAGIC + nonce_prefix
    plaintext_sha256 = hashlib.sha256()

    with source.open("rb") as src, destination.open("wb") as dst:
        dst.write(header)
        chunk_index = 0
        while True:
            chunk = src.read(ENCRYPTED_BACKUP_CHUNK_SIZE)
            if not chunk:
                break
            plaintext_sha256.update(chunk)
            nonce = nonce_prefix + chunk_index.to_bytes(4, "big")
            encrypted = aesgcm.encrypt(nonce, chunk, header)
            dst.write(struct.pack(">I", len(encrypted)))
            dst.write(encrypted)
            chunk_index += 1

    encrypted_sha256 = sha256_file(destination)
    checksum_path = write_checksum(destination, encrypted_sha256)
    manifest_path = destination.with_suffix(destination.suffix + ".manifest.json")
    manifest = {
        "format": "rdkg-aesgcm-chunked-v1",
        "source_name": source.name,
        "encrypted_name": destination.name,
        "chunk_size": ENCRYPTED_BACKUP_CHUNK_SIZE,
        "chunks": chunk_index,
        "plaintext_sha256": plaintext_sha256.hexdigest(),
        "encrypted_sha256": encrypted_sha256,
        "key_env": key_env,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "destination": str(destination),
        "size_bytes": destination.stat().st_size,
        "sha256": encrypted_sha256,
        "checksum_file": str(checksum_path),
        "manifest_file": str(manifest_path),
        "plaintext_sha256": manifest["plaintext_sha256"],
        "algorithm": manifest["format"],
    }


def decrypt_backup_file(source: Path, destination: Path, key: str | None = None, key_env: str = DEFAULT_KEY_ENV) -> dict:
    source = source.expanduser().resolve()
    destination = destination.expanduser().resolve()
    aesgcm = AESGCM(_backup_key(key, key_env))
    if not source.exists():
        raise SystemExit(f"Encrypted backup not found: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    plaintext_sha256 = hashlib.sha256()

    try:
        with source.open("rb") as src, destination.open("wb") as dst:
            header = src.read(len(ENCRYPTED_BACKUP_MAGIC) + 8)
            if len(header) != len(ENCRYPTED_BACKUP_MAGIC) + 8 or not header.startswith(ENCRYPTED_BACKUP_MAGIC):
                raise SystemExit("Unsupported encrypted backup format.")
            nonce_prefix = header[len(ENCRYPTED_BACKUP_MAGIC):]
            chunk_index = 0
            while True:
                length_bytes = src.read(4)
                if not length_bytes:
                    break
                if len(length_bytes) != 4:
                    raise SystemExit("Encrypted backup is truncated.")
                encrypted_length = struct.unpack(">I", length_bytes)[0]
                encrypted = src.read(encrypted_length)
                if len(encrypted) != encrypted_length:
                    raise SystemExit("Encrypted backup is truncated.")
                nonce = nonce_prefix + chunk_index.to_bytes(4, "big")
                chunk = aesgcm.decrypt(nonce, encrypted, header)
                plaintext_sha256.update(chunk)
                dst.write(chunk)
                chunk_index += 1
    except InvalidTag as exc:
        raise SystemExit("Encrypted backup authentication failed; check the backup key or file integrity.") from exc

    return {
        "source": str(source),
        "destination": str(destination),
        "plaintext_sha256": plaintext_sha256.hexdigest(),
    }


def backup_database(
    destination: Path | None = None,
    encrypted: bool = False,
    key: str | None = None,
    key_env: str = DEFAULT_KEY_ENV,
    keep_plaintext: bool = False,
    offsite_dir: Path | str | None = None,
) -> dict:
    source = DB_PATH
    if not source.exists():
        raise SystemExit(f"Database not found: {source}")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if destination is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = BACKUP_DIR / f"rd_knowledge_{stamp}.sqlite"
    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(source) as src, sqlite3.connect(destination) as dst:
        src.backup(dst)
    checksum = sha256_file(destination)
    checksum_path = write_checksum(destination, checksum)
    if encrypted:
        encrypted_payload = encrypt_backup_file(destination, key=key, key_env=key_env)
        if not keep_plaintext:
            destination.unlink(missing_ok=True)
            checksum_path.unlink(missing_ok=True)
        payload = {
            "action": "backup",
            "source": str(source),
            "destination": encrypted_payload["destination"],
            "encrypted": True,
            "plaintext_removed": not keep_plaintext,
            **{key: value for key, value in encrypted_payload.items() if key != "destination"},
        }
        if offsite_dir is not None:
            payload["offsite"] = copy_backup_artifacts(payload, offsite_dir)
        return payload
    payload = {
        "action": "backup",
        "source": str(source),
        "destination": str(destination),
        "encrypted": False,
        "size_bytes": destination.stat().st_size,
        "sha256": checksum,
        "checksum_file": str(checksum_path),
    }
    if offsite_dir is not None:
        payload["offsite"] = copy_backup_artifacts(payload, offsite_dir)
    return payload


def database_health_report(
    db_path: Path | str,
    min_counts: dict[str, int] | None = None,
    require_embeddings: bool = False,
) -> dict:
    min_counts = dict(DEFAULT_DRILL_MIN_COUNTS if min_counts is None else min_counts)
    path = Path(db_path).expanduser().resolve()
    report = {
        "path": str(path),
        "exists": path.exists(),
        "integrity_check": None,
        "counts": {},
        "fts_count": None,
        "embedding_count": None,
        "embedding_coverage": None,
        "issues": [],
        "ok": False,
    }
    if not path.exists():
        report["issues"].append("database file does not exist")
        return report
    try:
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            report["integrity_check"] = integrity
            if integrity != "ok":
                report["issues"].append(f"integrity_check failed: {integrity}")
            for table, minimum in min_counts.items():
                if not _table_exists(conn, table):
                    report["issues"].append(f"missing table: {table}")
                    continue
                count = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                report["counts"][table] = count
                if count < int(minimum):
                    report["issues"].append(f"table {table} count {count} is below minimum {minimum}")
            if _table_exists(conn, "documents_fts"):
                report["fts_count"] = int(conn.execute("SELECT COUNT(*) FROM documents_fts").fetchone()[0])
            if _table_exists(conn, "document_embeddings"):
                report["embedding_count"] = int(conn.execute("SELECT COUNT(*) FROM document_embeddings").fetchone()[0])
                document_count = int(report["counts"].get("documents") or 0)
                if document_count <= 0 and _table_exists(conn, "documents"):
                    document_count = int(conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0])
                report["embedding_coverage"] = round(report["embedding_count"] / document_count, 6) if document_count else 0.0
                if require_embeddings and report["embedding_coverage"] < 1.0:
                    report["issues"].append("document_embeddings coverage is below 1.0")
            elif require_embeddings:
                report["issues"].append("document_embeddings table is missing")
    except sqlite3.Error as exc:
        report["issues"].append(f"database health check failed: {exc}")
    report["ok"] = not report["issues"]
    return report


def restore_drill(
    backup_path: Path,
    key: str | None = None,
    key_env: str = DEFAULT_KEY_ENV,
    min_counts: dict[str, int] | None = None,
    require_embeddings: bool = False,
    temp_dir: Path | str | None = None,
) -> dict:
    backup_path = backup_path.expanduser().resolve()
    if not backup_path.exists():
        raise SystemExit(f"Backup not found: {backup_path}")
    drill_parent = Path(temp_dir).expanduser().resolve() if temp_dir is not None else BACKUP_DIR
    drill_parent.mkdir(parents=True, exist_ok=True)
    restored_from_encrypted = backup_path.suffix == ".enc"
    with tempfile.TemporaryDirectory(prefix="rdkg_restore_drill_", dir=drill_parent) as tmpdir:
        drill_db = Path(tmpdir) / "restored.sqlite"
        if restored_from_encrypted:
            decrypt_backup_file(backup_path, drill_db, key=key, key_env=key_env)
        else:
            with sqlite3.connect(backup_path) as src, sqlite3.connect(drill_db) as dst:
                src.backup(dst)
        report = database_health_report(drill_db, min_counts=min_counts, require_embeddings=require_embeddings)
        restored_sha256 = sha256_file(drill_db)
    return {
        "action": "restore_drill",
        "source": str(backup_path),
        "encrypted": restored_from_encrypted,
        "destructive": False,
        "active_database": str(DB_PATH),
        "restored_sha256": restored_sha256,
        "health": report,
        "ok": bool(report["ok"]),
    }


def run_backup_plan(
    config_path: Path | str | None = None,
    plan: dict | None = None,
    key: str | None = None,
    dry_run: bool = False,
) -> dict:
    backup_plan = _deep_merge(DEFAULT_BACKUP_PLAN, plan or {}) if plan is not None else load_backup_plan(config_path)
    backup_dir = _resolve_plan_path(backup_plan.get("backup_dir")) or BACKUP_DIR
    offsite_dir = _resolve_plan_path(backup_plan.get("offsite_dir"))
    key_env = str(backup_plan.get("key_env") or DEFAULT_KEY_ENV)
    encrypted = bool(backup_plan.get("encrypted", True))
    keep_plaintext = bool(backup_plan.get("keep_plaintext", False))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    planned_destination = backup_dir / f"rd_knowledge_{stamp}.sqlite"

    retention_plan = dict(backup_plan.get("retention") or {})
    offsite_retention_plan = dict(backup_plan.get("offsite_retention") or {})
    drill_plan = dict(backup_plan.get("restore_drill") or {})

    result = {
        "action": "run_plan",
        "config": str(Path(config_path).expanduser().resolve()) if config_path is not None else None,
        "dry_run": dry_run,
        "backup_dir": str(backup_dir),
        "offsite_dir": str(offsite_dir) if offsite_dir is not None else None,
        "encrypted": encrypted,
        "key_env": key_env,
    }

    if dry_run:
        result["backup"] = {
            "planned_destination": str(planned_destination.with_suffix(planned_destination.suffix + ".enc") if encrypted else planned_destination),
            "encrypted": encrypted,
            "would_create": True,
        }
        result["restore_drill"] = {
            "enabled": bool(drill_plan.get("enabled", True)),
            "would_run": bool(drill_plan.get("enabled", True)),
        }
    else:
        backup = backup_database(
            planned_destination,
            encrypted=encrypted,
            key=key,
            key_env=key_env,
            keep_plaintext=keep_plaintext,
            offsite_dir=offsite_dir,
        )
        result["backup"] = backup
        if bool(drill_plan.get("enabled", True)):
            result["restore_drill"] = restore_drill(
                Path(backup["destination"]),
                key=key,
                key_env=key_env,
                min_counts=dict(drill_plan.get("min_counts") or {}),
                require_embeddings=bool(drill_plan.get("require_embeddings", False)),
                temp_dir=backup_dir,
            )
            if not result["restore_drill"]["ok"]:
                result["ok"] = False
                return result
        else:
            result["restore_drill"] = {"enabled": False, "ok": None}

    result["retention"] = prune_backup_artifacts(
        backup_dir,
        pattern=str(retention_plan.get("pattern") or "rd_knowledge_*.sqlite*"),
        keep_latest=retention_plan.get("keep_latest"),
        max_age_days=retention_plan.get("max_age_days"),
        dry_run=dry_run,
    )
    if offsite_dir is not None:
        result["offsite_retention"] = prune_backup_artifacts(
            offsite_dir,
            pattern=str(offsite_retention_plan.get("pattern") or retention_plan.get("pattern") or "rd_knowledge_*.sqlite*"),
            keep_latest=offsite_retention_plan.get("keep_latest"),
            max_age_days=offsite_retention_plan.get("max_age_days"),
            dry_run=dry_run,
        )
    result["ok"] = not dry_run and bool(result.get("backup")) and result.get("restore_drill", {}).get("ok") is not False
    if dry_run:
        result["ok"] = True
    return result


def restore_database(backup_path: Path, force: bool = False, key: str | None = None, key_env: str = DEFAULT_KEY_ENV) -> dict:
    backup_path = backup_path.expanduser().resolve()
    if not backup_path.exists():
        raise SystemExit(f"Backup not found: {backup_path}")
    if not force:
        raise SystemExit("Restore overwrites the active database. Re-run with --force to confirm.")

    pre_restore = backup_database(BACKUP_DIR / f"pre_restore_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.sqlite")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    restored_from_encrypted = backup_path.suffix == ".enc"
    decrypted_temp: Path | None = None
    restore_source = backup_path
    if restored_from_encrypted:
        with tempfile.NamedTemporaryFile(prefix="rdkg_restore_", suffix=".sqlite", dir=BACKUP_DIR, delete=False) as tmp:
            decrypted_temp = Path(tmp.name)
        decrypt_backup_file(backup_path, decrypted_temp, key=key, key_env=key_env)
        restore_source = decrypted_temp
    try:
        with sqlite3.connect(restore_source) as src, sqlite3.connect(DB_PATH) as dst:
            src.backup(dst)
    finally:
        if decrypted_temp is not None:
            decrypted_temp.unlink(missing_ok=True)
    return {
        "action": "restore",
        "source": str(backup_path),
        "destination": str(DB_PATH),
        "encrypted": restored_from_encrypted,
        "restored_sha256": sha256_file(DB_PATH),
        "pre_restore_backup": pre_restore,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Backup or restore the local SQLite knowledge base.")
    sub = parser.add_subparsers(dest="command", required=True)
    backup_parser = sub.add_parser("backup", help="Create a SQLite backup with a .sha256 sidecar")
    backup_parser.add_argument("--destination", type=Path, default=None)
    backup_parser.add_argument("--encrypted", action="store_true", help="Write an AES-GCM encrypted .enc backup")
    backup_parser.add_argument("--key", default=None, help=f"Urlsafe base64 encryption key. Prefer ${DEFAULT_KEY_ENV}.")
    backup_parser.add_argument("--key-env", default=DEFAULT_KEY_ENV)
    backup_parser.add_argument("--keep-plaintext", action="store_true", help="Keep the plaintext backup next to the encrypted file")
    backup_parser.add_argument("--offsite-dir", type=Path, default=None, help="Copy backup artifacts to a second directory")

    run_plan_parser = sub.add_parser("run-plan", help="Run configured backup, optional offsite copy, restore drill and retention")
    run_plan_parser.add_argument("--config", type=Path, default=None, help="JSON backup plan config. Defaults to built-in production-safe settings.")
    run_plan_parser.add_argument("--key", default=None, help=f"Urlsafe base64 encryption key. Prefer ${DEFAULT_KEY_ENV}.")
    run_plan_parser.add_argument("--dry-run", action="store_true", help="Show planned backup and retention actions without writing files")

    prune_parser = sub.add_parser("prune", help="Apply retention to backup artifacts and their sidecars")
    prune_parser.add_argument("--directory", type=Path, default=BACKUP_DIR)
    prune_parser.add_argument("--pattern", default="rd_knowledge_*.sqlite*")
    prune_parser.add_argument("--keep-latest", type=int, default=None)
    prune_parser.add_argument("--max-age-days", type=int, default=None)
    prune_parser.add_argument("--dry-run", action="store_true")

    restore_parser = sub.add_parser("restore", help="Restore the active SQLite DB from a backup")
    restore_parser.add_argument("backup", type=Path)
    restore_parser.add_argument("--force", action="store_true")
    restore_parser.add_argument("--key", default=None, help=f"Urlsafe base64 encryption key for .enc restore. Prefer ${DEFAULT_KEY_ENV}.")
    restore_parser.add_argument("--key-env", default=DEFAULT_KEY_ENV)

    drill_parser = sub.add_parser("restore-drill", help="Restore a backup into a temporary DB and validate it without touching the active DB")
    drill_parser.add_argument("backup", type=Path)
    drill_parser.add_argument("--key", default=None, help=f"Urlsafe base64 encryption key for .enc drill. Prefer ${DEFAULT_KEY_ENV}.")
    drill_parser.add_argument("--key-env", default=DEFAULT_KEY_ENV)
    drill_parser.add_argument("--require-embeddings", action="store_true")
    drill_parser.add_argument(
        "--min-count",
        action="append",
        default=[],
        metavar="TABLE=N",
        help="Override minimum restored table count; repeatable. Defaults: sources=1, documents=1, facts=1",
    )

    sub.add_parser("generate-key", help=f"Generate a backup encryption key for ${DEFAULT_KEY_ENV}")
    args = parser.parse_args()

    if args.command == "backup":
        payload = backup_database(
            args.destination,
            encrypted=args.encrypted,
            key=args.key,
            key_env=args.key_env,
            keep_plaintext=args.keep_plaintext,
            offsite_dir=args.offsite_dir,
        )
    elif args.command == "run-plan":
        payload = run_backup_plan(args.config, key=args.key, dry_run=args.dry_run)
    elif args.command == "prune":
        payload = prune_backup_artifacts(
            args.directory,
            pattern=args.pattern,
            keep_latest=args.keep_latest,
            max_age_days=args.max_age_days,
            dry_run=args.dry_run,
        )
    elif args.command == "restore":
        payload = restore_database(args.backup, force=args.force, key=args.key, key_env=args.key_env)
    elif args.command == "restore-drill":
        min_counts = dict(DEFAULT_DRILL_MIN_COUNTS)
        for item in args.min_count:
            if "=" not in item:
                raise SystemExit("--min-count must use TABLE=N")
            table, value = item.split("=", 1)
            min_counts[table.strip()] = int(value)
        payload = restore_drill(
            args.backup,
            key=args.key,
            key_env=args.key_env,
            min_counts=min_counts,
            require_embeddings=args.require_embeddings,
        )
    else:
        payload = {"action": "generate_key", "key_env": DEFAULT_KEY_ENV, "key": generate_backup_key()}
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
