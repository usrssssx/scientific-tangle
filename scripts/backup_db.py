from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
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
        return {
            "action": "backup",
            "source": str(source),
            "destination": encrypted_payload["destination"],
            "encrypted": True,
            "plaintext_removed": not keep_plaintext,
            **{key: value for key, value in encrypted_payload.items() if key != "destination"},
        }
    return {
        "action": "backup",
        "source": str(source),
        "destination": str(destination),
        "encrypted": False,
        "size_bytes": destination.stat().st_size,
        "sha256": checksum,
        "checksum_file": str(checksum_path),
    }


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

    restore_parser = sub.add_parser("restore", help="Restore the active SQLite DB from a backup")
    restore_parser.add_argument("backup", type=Path)
    restore_parser.add_argument("--force", action="store_true")
    restore_parser.add_argument("--key", default=None, help=f"Urlsafe base64 encryption key for .enc restore. Prefer ${DEFAULT_KEY_ENV}.")
    restore_parser.add_argument("--key-env", default=DEFAULT_KEY_ENV)

    sub.add_parser("generate-key", help=f"Generate a backup encryption key for ${DEFAULT_KEY_ENV}")
    args = parser.parse_args()

    if args.command == "backup":
        payload = backup_database(
            args.destination,
            encrypted=args.encrypted,
            key=args.key,
            key_env=args.key_env,
            keep_plaintext=args.keep_plaintext,
        )
    elif args.command == "restore":
        payload = restore_database(args.backup, force=args.force, key=args.key, key_env=args.key_env)
    else:
        payload = {"action": "generate_key", "key_env": DEFAULT_KEY_ENV, "key": generate_backup_key()}
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
