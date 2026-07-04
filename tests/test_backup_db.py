import base64
import sqlite3
from pathlib import Path

import scripts.backup_db as backup_db


def _write_value(db_path: Path, value: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT OR REPLACE INTO kv(key, value) VALUES ('state', ?)", (value,))


def _read_value(db_path: Path) -> str:
    with sqlite3.connect(db_path) as conn:
        return str(conn.execute("SELECT value FROM kv WHERE key = 'state'").fetchone()[0])


def test_generate_backup_key_returns_aes_key_material():
    key = backup_db.generate_backup_key()

    assert len(base64.urlsafe_b64decode(key.encode("ascii"))) == 32


def test_encrypted_backup_roundtrip_restores_sqlite_and_removes_plaintext(tmp_path, monkeypatch):
    db_path = tmp_path / "rdkg.sqlite"
    backup_dir = tmp_path / "backups"
    plaintext_backup = tmp_path / "rdkg-backup.sqlite"
    _write_value(db_path, "before")
    monkeypatch.setattr(backup_db, "DB_PATH", db_path)
    monkeypatch.setattr(backup_db, "BACKUP_DIR", backup_dir)
    key = backup_db.generate_backup_key()

    payload = backup_db.backup_database(plaintext_backup, encrypted=True, key=key)
    _write_value(db_path, "after")
    restored = backup_db.restore_database(Path(payload["destination"]), force=True, key=key)

    assert payload["encrypted"] is True
    assert payload["destination"].endswith(".sqlite.enc")
    assert payload["plaintext_removed"] is True
    assert not plaintext_backup.exists()
    assert Path(payload["destination"]).exists()
    assert Path(payload["checksum_file"]).exists()
    assert Path(payload["manifest_file"]).exists()
    assert restored["encrypted"] is True
    assert _read_value(db_path) == "before"
    assert not list(backup_dir.glob("rdkg_restore_*.sqlite"))
