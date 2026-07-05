import base64
import os
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


def _write_artifact(path: Path, timestamp: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(path.name, encoding="utf-8")
    os.utime(path, (timestamp, timestamp))


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


def test_backup_can_copy_artifacts_to_offsite_dir(tmp_path, monkeypatch):
    db_path = tmp_path / "rdkg.sqlite"
    backup_dir = tmp_path / "backups"
    offsite_dir = tmp_path / "offsite"
    plaintext_backup = backup_dir / "rdkg-backup.sqlite"
    _write_value(db_path, "state")
    monkeypatch.setattr(backup_db, "DB_PATH", db_path)
    monkeypatch.setattr(backup_db, "BACKUP_DIR", backup_dir)

    payload = backup_db.backup_database(plaintext_backup, offsite_dir=offsite_dir)

    copied = payload["offsite"]["copied"]
    copied_names = {Path(item["destination"]).name for item in copied}
    assert copied_names == {plaintext_backup.name, plaintext_backup.with_suffix(".sqlite.sha256").name}
    for item in copied:
        assert Path(item["destination"]).exists()
        assert item["sha256"] == backup_db.sha256_file(Path(item["destination"]))


def test_restore_drill_validates_backup_without_overwriting_active_db(tmp_path, monkeypatch):
    db_path = tmp_path / "rdkg.sqlite"
    backup_dir = tmp_path / "backups"
    backup_path = backup_dir / "drill.sqlite"
    _write_value(db_path, "before")
    monkeypatch.setattr(backup_db, "DB_PATH", db_path)
    monkeypatch.setattr(backup_db, "BACKUP_DIR", backup_dir)
    payload = backup_db.backup_database(backup_path)
    _write_value(db_path, "after")

    drill = backup_db.restore_drill(Path(payload["destination"]), min_counts={})

    assert drill["ok"] is True
    assert drill["destructive"] is False
    assert drill["health"]["integrity_check"] == "ok"
    assert _read_value(db_path) == "after"
    assert not list(backup_dir.glob("rdkg_restore_drill_*"))


def test_restore_drill_validates_encrypted_backup(tmp_path, monkeypatch):
    db_path = tmp_path / "rdkg.sqlite"
    backup_dir = tmp_path / "backups"
    backup_path = backup_dir / "drill.sqlite"
    _write_value(db_path, "encrypted")
    monkeypatch.setattr(backup_db, "DB_PATH", db_path)
    monkeypatch.setattr(backup_db, "BACKUP_DIR", backup_dir)
    key = backup_db.generate_backup_key()
    payload = backup_db.backup_database(backup_path, encrypted=True, key=key)

    drill = backup_db.restore_drill(Path(payload["destination"]), key=key, min_counts={})

    assert drill["ok"] is True
    assert drill["encrypted"] is True
    assert drill["health"]["integrity_check"] == "ok"


def test_prune_backup_artifacts_removes_sidecars_beyond_latest(tmp_path):
    backup_dir = tmp_path / "backups"
    old_backup = backup_dir / "rd_knowledge_20260101T000000Z.sqlite"
    new_backup = backup_dir / "rd_knowledge_20260102T000000Z.sqlite"
    _write_artifact(old_backup, 1_700_000_000)
    _write_artifact(old_backup.with_suffix(".sqlite.sha256"), 1_700_000_000)
    _write_artifact(new_backup, 1_700_100_000)
    _write_artifact(new_backup.with_suffix(".sqlite.sha256"), 1_700_100_000)

    dry_run = backup_db.prune_backup_artifacts(backup_dir, keep_latest=1, dry_run=True)

    assert old_backup.exists()
    assert {Path(item["path"]).name for item in dry_run["would_delete"]} == {
        old_backup.name,
        old_backup.with_suffix(".sqlite.sha256").name,
    }

    actual = backup_db.prune_backup_artifacts(backup_dir, keep_latest=1)

    assert not old_backup.exists()
    assert not old_backup.with_suffix(".sqlite.sha256").exists()
    assert new_backup.exists()
    assert new_backup.with_suffix(".sqlite.sha256").exists()
    assert {Path(item["path"]).name for item in actual["deleted"]} == {
        old_backup.name,
        old_backup.with_suffix(".sqlite.sha256").name,
    }


def test_run_backup_plan_creates_encrypted_offsite_drill_and_retention(tmp_path, monkeypatch):
    db_path = tmp_path / "rdkg.sqlite"
    backup_dir = tmp_path / "backups"
    offsite_dir = tmp_path / "offsite"
    old_backup = backup_dir / "rd_knowledge_20250101T000000Z.sqlite"
    _write_value(db_path, "scheduled")
    _write_artifact(old_backup, 1_600_000_000)
    _write_artifact(old_backup.with_suffix(".sqlite.sha256"), 1_600_000_000)
    monkeypatch.setattr(backup_db, "DB_PATH", db_path)
    monkeypatch.setattr(backup_db, "BACKUP_DIR", backup_dir)
    key = backup_db.generate_backup_key()
    monkeypatch.setenv("RD_TEST_BACKUP_KEY", key)

    result = backup_db.run_backup_plan(
        plan={
            "backup_dir": str(backup_dir),
            "encrypted": True,
            "key_env": "RD_TEST_BACKUP_KEY",
            "offsite_dir": str(offsite_dir),
            "retention": {"keep_latest": 1, "max_age_days": None},
            "offsite_retention": {"keep_latest": 1, "max_age_days": None},
            "restore_drill": {"enabled": True, "min_counts": {}},
        }
    )

    destination = Path(result["backup"]["destination"])
    copied_names = {Path(item["destination"]).name for item in result["backup"]["offsite"]["copied"]}
    assert result["ok"] is True
    assert result["backup"]["encrypted"] is True
    assert destination.suffix == ".enc"
    assert destination.exists()
    assert result["restore_drill"]["ok"] is True
    assert copied_names == {
        destination.name,
        destination.with_suffix(".enc.sha256").name,
        destination.with_suffix(".enc.manifest.json").name,
    }
    assert not old_backup.exists()
    assert not old_backup.with_suffix(".sqlite.sha256").exists()
    assert result["retention"]["primary_count"] == 2
