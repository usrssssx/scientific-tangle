from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any

from .field_encryption import FIELD_ENCRYPTION_KEY_ENV

REQUIRE_STORAGE_ENCRYPTION_ENV = "RD_KG_REQUIRE_STORAGE_ENCRYPTION"
STORAGE_PROVIDER_ENV = "RD_KG_STORAGE_ENCRYPTION_PROVIDER"
STORAGE_EVIDENCE_ENV = "RD_KG_STORAGE_ENCRYPTION_EVIDENCE"
STORAGE_EVIDENCE_FILE_ENV = "RD_KG_STORAGE_ENCRYPTION_EVIDENCE_FILE"
SQLCIPHER_KEY_ENV = "RD_KG_SQLCIPHER_KEY"
SQLCIPHER_KEY_FILE_ENV = "RD_KG_SQLCIPHER_KEY_FILE"
BACKUP_KEY_ENV = "RD_KG_BACKUP_KEY"
FULL_STORAGE_PROVIDERS = {"encrypted_volume", "managed_encrypted_db", "sqlcipher"}


class StorageEncryptionError(RuntimeError):
    pass


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_or_file(name: str, file_name: str) -> str | None:
    value = os.getenv(name)
    if value:
        return value.strip()
    path_value = os.getenv(file_name)
    if not path_value:
        return None
    path = Path(path_value).expanduser()
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise StorageEncryptionError(f"{file_name} cannot be read: {path}") from exc


def _key_summary(value: str | None) -> dict[str, Any]:
    if not value:
        return {"configured": False, "valid": False}
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
    except Exception:  # noqa: BLE001 - report config state without leaking secret material
        return {"configured": True, "valid": False, "reason": "not urlsafe base64"}
    valid = len(raw) in {16, 24, 32}
    summary = {
        "configured": True,
        "valid": valid,
        "bytes": len(raw),
        "fingerprint": hashlib.sha256(raw).hexdigest()[:16],
    }
    if not valid:
        summary["reason"] = "key must decode to 16, 24, or 32 bytes"
    return summary


def _field_encryption_report() -> dict[str, Any]:
    summary = _key_summary(os.getenv(FIELD_ENCRYPTION_KEY_ENV, "").strip() or None)
    return {
        "enabled": bool(summary["configured"] and summary["valid"]),
        "key": summary,
        "covered_fields": [
            "sources.path",
            "sources.abstract",
            "experts.contact",
            "audit_log.object_id",
            "audit_log.details_json",
            "export_approvals.reason",
            "export_approvals.justification",
            "export_approvals.review_comment",
            "policy_decisions.reason",
            "policy_decisions.resource_json",
            "policy_decisions.external_json",
        ],
    }


def _sqlcipher_available() -> bool:
    try:
        __import__("pysqlcipher3")
        return True
    except Exception:  # noqa: BLE001 - optional runtime dependency
        return False


def _storage_evidence() -> dict[str, Any]:
    inline = os.getenv(STORAGE_EVIDENCE_ENV, "").strip()
    evidence_file = os.getenv(STORAGE_EVIDENCE_FILE_ENV, "").strip()
    if inline:
        return {"configured": True, "source": STORAGE_EVIDENCE_ENV, "value": inline}
    if evidence_file:
        path = Path(evidence_file).expanduser()
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            return {"configured": False, "source": STORAGE_EVIDENCE_FILE_ENV, "path": str(path), "reason": str(exc)}
        return {"configured": bool(value), "source": STORAGE_EVIDENCE_FILE_ENV, "path": str(path), "value": value}
    return {"configured": False}


def storage_encryption_required() -> bool:
    return _env_bool(REQUIRE_STORAGE_ENCRYPTION_ENV)


def storage_encryption_report(db_path: Path | str | None = None) -> dict[str, Any]:
    required = storage_encryption_required()
    provider = (os.getenv(STORAGE_PROVIDER_ENV, "none") or "none").strip().lower()
    db_path_value = str(Path(db_path).expanduser()) if db_path is not None else None
    evidence = _storage_evidence()
    field_level = _field_encryption_report()
    sqlcipher_key = _key_summary(_env_or_file(SQLCIPHER_KEY_ENV, SQLCIPHER_KEY_FILE_ENV))
    backup_key = _key_summary(os.getenv(BACKUP_KEY_ENV, "").strip() or None)

    issues: list[str] = []
    if provider not in FULL_STORAGE_PROVIDERS | {"none"}:
        issues.append(f"Unsupported {STORAGE_PROVIDER_ENV}: {provider}")

    full_storage_configured = False
    if provider in {"encrypted_volume", "managed_encrypted_db"}:
        full_storage_configured = bool(evidence.get("configured"))
        if not full_storage_configured:
            issues.append(f"{provider} requires {STORAGE_EVIDENCE_ENV} or {STORAGE_EVIDENCE_FILE_ENV}")
    elif provider == "sqlcipher":
        full_storage_configured = bool(sqlcipher_key["configured"] and sqlcipher_key["valid"])
        if not sqlcipher_key["configured"]:
            issues.append(f"sqlcipher requires {SQLCIPHER_KEY_ENV} or {SQLCIPHER_KEY_FILE_ENV}")
        elif not sqlcipher_key["valid"]:
            issues.append(f"{SQLCIPHER_KEY_ENV} is invalid")

    if required and provider == "none":
        issues.append(f"{REQUIRE_STORAGE_ENCRYPTION_ENV}=true requires {STORAGE_PROVIDER_ENV}=encrypted_volume|managed_encrypted_db|sqlcipher")
    if required and not field_level["enabled"]:
        issues.append(f"{REQUIRE_STORAGE_ENCRYPTION_ENV}=true requires valid {FIELD_ENCRYPTION_KEY_ENV} for sensitive DB fields")
    if required and provider in FULL_STORAGE_PROVIDERS and not full_storage_configured:
        issues.append("Full-storage encryption provider is not configured")

    ok = not issues if required else True
    return {
        "ok": ok,
        "required": required,
        "status": "ready" if ok and required else "not_required" if not required else "blocked",
        "db_path": db_path_value,
        "provider": provider,
        "full_storage_configured": full_storage_configured,
        "field_level": field_level,
        "database_storage": {
            "provider": provider,
            "evidence": evidence,
            "sqlcipher_key": sqlcipher_key,
            "sqlcipher_runtime_available": _sqlcipher_available(),
        },
        "backup_encryption": {
            "default_key_env": BACKUP_KEY_ENV,
            "key": backup_key,
            "run_plan_defaults_encrypted": True,
        },
        "issues": issues,
    }


def enforce_storage_encryption_ready(db_path: Path | str | None = None) -> dict[str, Any]:
    report = storage_encryption_report(db_path)
    if report["required"] and not report["ok"]:
        raise StorageEncryptionError("Storage encryption is not ready: " + "; ".join(report["issues"]))
    return report
