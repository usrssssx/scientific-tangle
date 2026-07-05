from contextlib import contextmanager
import json

import pytest
from fastapi import HTTPException

import app.main as main_module
from app.config import PROJECT_ROOT
from app.db import connect, create_schema
from app.field_encryption import generate_field_encryption_key
from app.security import AccessContext
from app.security_review import security_review_report


REVIEW_ENV_VARS = [
    "RD_KG_OIDC_REQUIRED",
    "RD_KG_OIDC_ISSUER",
    "RD_KG_OIDC_AUDIENCE",
    "RD_KG_OIDC_JWKS_JSON",
    "RD_KG_DIRECTORY_REQUIRED",
    "RD_KG_POLICY_ENGINE_URL",
    "RD_KG_POLICY_ENGINE_BEARER_TOKEN",
    "RD_KG_POLICY_ENGINE_BUNDLE_REF",
    "RD_KG_POLICY_ENGINE_HA_ENDPOINTS",
    "RD_KG_POLICY_ENGINE_HA",
    "RD_KG_POLICY_DECISION_AUDIT",
    "RD_KG_REQUIRE_STORAGE_ENCRYPTION",
    "RD_KG_FIELD_ENCRYPTION_KEY",
    "RD_KG_STORAGE_ENCRYPTION_PROVIDER",
    "RD_KG_STORAGE_ENCRYPTION_EVIDENCE",
    "RD_KG_SIEM_EXPORT_URL",
    "RD_KG_LOG_ARCHIVE_TARGET",
    "RD_KG_ALERT_WEBHOOK_URL",
    "RD_KG_PAGERDUTY_ROUTING_KEY",
    "RD_KG_LOG_RETENTION_DAYS",
    "RD_KG_METRICS_RETENTION_DAYS",
    "RD_KG_TRACE_RETENTION_DAYS",
    "RD_KG_DR_IMMUTABLE_OFFSITE_URI",
    "RD_KG_DR_ENVIRONMENT_ID",
    "RD_KG_DR_MONITOR_URL",
    "RD_KG_DR_ALERT_WEBHOOK_URL",
    "RD_KG_SECURITY_REVIEW_EVIDENCE_FILE",
    "RD_KG_DIRECTORY_SYNC_CONFIG",
    "RD_KG_LDAP_BIND_PASSWORD",
]


def _clear_review_env(monkeypatch):
    for name in REVIEW_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _write_review_evidence(path):
    payload = {
        "review_id": "rdkg-sec-review-test",
        "status": "approved",
        "approved_at": "2026-07-05",
        "expires_at": "2999-12-31",
        "redacted": True,
        "approved_by": [{"name": "Security Reviewer", "role": "security"}],
        "scope": {"environment": "production", "system": "rdkg-test"},
        "control_evidence": {
            "identity": [{"ref": "IDENTITY-1", "sha256": "a" * 64}],
            "authorization": [{"ref": "AUTHZ-1", "sha256": "b" * 64}],
            "dlp": [{"ref": "DLP-1", "sha256": "c" * 64}],
            "encryption": [{"ref": "ENC-1", "sha256": "d" * 64}],
            "observability": [{"ref": "OBS-1", "sha256": "e" * 64}],
            "backup_restore": [{"ref": "BACKUP-1", "sha256": "f" * 64}],
            "disaster_recovery": [{"ref": "DR-1", "sha256": "1" * 64}],
            "load_test": [{"ref": "SLA-1", "sha256": "2" * 64}],
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _set_passing_production_review_env(monkeypatch, tmp_path):
    _clear_review_env(monkeypatch)
    monkeypatch.setenv("RD_KG_OIDC_REQUIRED", "true")
    monkeypatch.setenv("RD_KG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("RD_KG_OIDC_AUDIENCE", "rdkg")
    monkeypatch.setenv("RD_KG_OIDC_JWKS_JSON", json.dumps({"keys": [{"kty": "RSA", "kid": "review"}]}))
    monkeypatch.setenv("RD_KG_DIRECTORY_REQUIRED", "true")
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_URL", "https://policy.example/v1/data/rdkg/allow")
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_BEARER_TOKEN", "policy-token")
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_BUNDLE_REF", "opa-bundle:v1.2.3")
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_HA_ENDPOINTS", "https://pdp-a.example,https://pdp-b.example")
    monkeypatch.setenv("RD_KG_POLICY_DECISION_AUDIT", "true")
    monkeypatch.setenv("RD_KG_REQUIRE_STORAGE_ENCRYPTION", "true")
    monkeypatch.setenv("RD_KG_FIELD_ENCRYPTION_KEY", generate_field_encryption_key())
    monkeypatch.setenv("RD_KG_STORAGE_ENCRYPTION_PROVIDER", "managed_encrypted_db")
    monkeypatch.setenv("RD_KG_STORAGE_ENCRYPTION_EVIDENCE", "rds:storageEncrypted=true:kmsKeyId=alias/rdkg")
    monkeypatch.setenv("RD_KG_SIEM_EXPORT_URL", "https://siem.example/ingest")
    monkeypatch.setenv("RD_KG_ALERT_WEBHOOK_URL", "https://alerts.example/rdkg")
    monkeypatch.setenv("RD_KG_LOG_RETENTION_DAYS", "180")
    monkeypatch.setenv("RD_KG_METRICS_RETENTION_DAYS", "180")
    monkeypatch.setenv("RD_KG_TRACE_RETENTION_DAYS", "60")
    monkeypatch.setenv("RD_KG_DR_IMMUTABLE_OFFSITE_URI", "s3://rdkg-dr-lock/backups")
    monkeypatch.setenv("RD_KG_DR_ENVIRONMENT_ID", "dr-region-1")
    monkeypatch.setenv("RD_KG_DR_MONITOR_URL", "https://monitor.example/dr")
    evidence_path = _write_review_evidence(tmp_path / "security-review-evidence.json")
    monkeypatch.setenv("RD_KG_SECURITY_REVIEW_EVIDENCE_FILE", str(evidence_path))
    monkeypatch.setenv("RD_KG_DIRECTORY_SYNC_CONFIG", str(PROJECT_ROOT / "ops/directory_sync.example.json"))
    monkeypatch.setenv("RD_KG_LDAP_BIND_PASSWORD", "not-used-in-test")


def test_security_review_local_profile_reports_warnings_without_failing(monkeypatch, tmp_path):
    _clear_review_env(monkeypatch)

    report = security_review_report(profile="local", db_path=tmp_path / "local.sqlite")

    assert report["profile"] == "local"
    assert report["passed"] is True
    assert report["overall_status"] in {"pass", "warn"}
    assert report["counts"]["fail"] == 0
    assert any(item["status"] == "warn" for item in report["controls"])


def test_security_review_production_profile_passes_with_required_evidence(monkeypatch, tmp_path):
    _set_passing_production_review_env(monkeypatch, tmp_path)

    report = security_review_report(profile="production", db_path=tmp_path / "production.sqlite")

    assert report["overall_status"] == "pass"
    assert report["passed"] is True
    assert report["counts"]["fail"] == 0
    assert report["counts"]["warn"] == 0
    assert {item["id"] for item in report["controls"]} >= {
        "auth.oidc_required",
        "auth.ad_ldap_sync",
        "authorization.external_pdp",
        "encryption.storage_at_rest",
        "observability.enterprise_retention_and_alerting",
        "dr.independent_environment",
        "sla.synthetic_1m_profile",
        "review.external_signoff",
    }


def test_security_review_production_profile_fails_missing_evidence(monkeypatch, tmp_path):
    _clear_review_env(monkeypatch)

    report = security_review_report(profile="production", db_path=tmp_path / "missing.sqlite")

    assert report["overall_status"] == "fail"
    assert report["passed"] is False
    assert report["counts"]["fail"] > 0
    assert any(item["id"] == "auth.oidc_required" and item["status"] == "fail" for item in report["controls"])


def test_security_review_endpoint_is_admin_only_and_audited(monkeypatch, tmp_path):
    _clear_review_env(monkeypatch)
    db_path = tmp_path / "review-endpoint.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)

    @contextmanager
    def fake_connect():
        with connect(db_path) as conn:
            yield conn

    monkeypatch.setattr(main_module, "DB_PATH", db_path)
    monkeypatch.setattr(main_module, "connect", fake_connect)

    response = main_module.security_review(profile="local", context=AccessContext(role="admin", subject="admin-1"))
    payload = json.loads(response.body)

    assert response.status_code == 200
    assert payload["profile"] == "local"
    with connect(db_path) as conn:
        audit_actions = [row["action"] for row in conn.execute("SELECT action FROM audit_log ORDER BY id").fetchall()]
    assert "security_review" in audit_actions

    with pytest.raises(HTTPException) as exc_info:
        main_module.security_review(profile="local", context=AccessContext(role="manager", subject="manager-1"))
    assert exc_info.value.status_code == 403

    with pytest.raises(HTTPException) as bad_profile:
        main_module.security_review(profile="staging", context=AccessContext(role="admin", subject="admin-1"))
    assert bad_profile.value.status_code == 400
