from contextlib import contextmanager
import json

import pytest
from fastapi import HTTPException

import app.main as main_module
from app.db import connect, create_schema
from app.field_encryption import generate_field_encryption_key
from app.security import AccessContext
from app.storage_encryption import (
    BACKUP_KEY_ENV,
    FIELD_ENCRYPTION_KEY_ENV,
    REQUIRE_STORAGE_ENCRYPTION_ENV,
    SQLCIPHER_KEY_ENV,
    SQLCIPHER_KEY_FILE_ENV,
    STORAGE_EVIDENCE_ENV,
    STORAGE_EVIDENCE_FILE_ENV,
    STORAGE_PROVIDER_ENV,
    StorageEncryptionError,
    enforce_storage_encryption_ready,
    storage_encryption_report,
)


STORAGE_ENV_VARS = [
    REQUIRE_STORAGE_ENCRYPTION_ENV,
    STORAGE_PROVIDER_ENV,
    STORAGE_EVIDENCE_ENV,
    STORAGE_EVIDENCE_FILE_ENV,
    FIELD_ENCRYPTION_KEY_ENV,
    SQLCIPHER_KEY_ENV,
    SQLCIPHER_KEY_FILE_ENV,
    BACKUP_KEY_ENV,
]


def _clear_storage_env(monkeypatch):
    for name in STORAGE_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_storage_encryption_required_blocks_without_provider_or_field_key(monkeypatch, tmp_path):
    _clear_storage_env(monkeypatch)
    monkeypatch.setenv(REQUIRE_STORAGE_ENCRYPTION_ENV, "true")

    report = storage_encryption_report(tmp_path / "rdkg.sqlite")

    assert not report["ok"]
    assert report["status"] == "blocked"
    assert report["provider"] == "none"
    assert any(STORAGE_PROVIDER_ENV in issue for issue in report["issues"])
    assert any(FIELD_ENCRYPTION_KEY_ENV in issue for issue in report["issues"])
    with pytest.raises(StorageEncryptionError):
        enforce_storage_encryption_ready(tmp_path / "rdkg.sqlite")


def test_storage_encryption_required_accepts_managed_provider_with_field_key(monkeypatch, tmp_path):
    _clear_storage_env(monkeypatch)
    field_key = generate_field_encryption_key()
    backup_key = generate_field_encryption_key()
    monkeypatch.setenv(REQUIRE_STORAGE_ENCRYPTION_ENV, "true")
    monkeypatch.setenv(STORAGE_PROVIDER_ENV, "managed_encrypted_db")
    monkeypatch.setenv(STORAGE_EVIDENCE_ENV, "aws-rds:storageEncrypted=true:kmsKeyId=alias/rdkg")
    monkeypatch.setenv(FIELD_ENCRYPTION_KEY_ENV, field_key)
    monkeypatch.setenv(BACKUP_KEY_ENV, backup_key)

    report = enforce_storage_encryption_ready(tmp_path / "rdkg.sqlite")

    assert report["ok"] is True
    assert report["status"] == "ready"
    assert report["full_storage_configured"] is True
    assert report["field_level"]["enabled"] is True
    assert report["field_level"]["key"]["fingerprint"]
    assert field_key not in json.dumps(report)
    assert backup_key not in json.dumps(report)
    assert report["backup_encryption"]["key"]["valid"] is True


def test_storage_encryption_endpoint_is_admin_only_and_audited(monkeypatch, tmp_path):
    _clear_storage_env(monkeypatch)
    db_path = tmp_path / "storage-endpoint.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)

    @contextmanager
    def fake_connect():
        with connect(db_path) as conn:
            yield conn

    monkeypatch.setattr(main_module, "DB_PATH", db_path)
    monkeypatch.setattr(main_module, "connect", fake_connect)

    response = main_module.security_storage_encryption(context=AccessContext(role="admin", subject="admin-1"))
    payload = json.loads(response.body)

    assert response.status_code == 200
    assert payload["status"] == "not_required"
    with connect(db_path) as conn:
        audit_actions = [row["action"] for row in conn.execute("SELECT action FROM audit_log ORDER BY id").fetchall()]
    assert "security_storage_encryption" in audit_actions

    with pytest.raises(HTTPException) as exc_info:
        main_module.security_storage_encryption(context=AccessContext(role="manager", subject="manager-1"))
    assert exc_info.value.status_code == 403
