from __future__ import annotations

import json
import os
import re
from datetime import date
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT

SECURITY_REVIEW_EVIDENCE_ENV = "RD_KG_SECURITY_REVIEW_EVIDENCE_FILE"
DEFAULT_SECURITY_REVIEW_EVIDENCE_PATH = PROJECT_ROOT / "ops/security_review_evidence.json"

REQUIRED_EVIDENCE_CATEGORIES = (
    "identity",
    "authorization",
    "dlp",
    "encryption",
    "observability",
    "backup_restore",
    "disaster_recovery",
    "load_test",
)
APPROVED_REVIEW_STATUSES = {"approved", "accepted", "passed", "pass"}
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
INLINE_SECRET_RE = re.compile(r"(password|api[_-]?key|access[_-]?token|refresh[_-]?token|secret)\s*[:=]\s*['\"]?[^'\"\s]{8,}", re.IGNORECASE)


def _resolve_evidence_path(path: str | Path | None = None) -> tuple[Path, bool]:
    if path is not None:
        return Path(path).expanduser(), True
    env_path = os.getenv(SECURITY_REVIEW_EVIDENCE_ENV, "").strip()
    if env_path:
        return Path(env_path).expanduser(), True
    return DEFAULT_SECURITY_REVIEW_EVIDENCE_PATH, DEFAULT_SECURITY_REVIEW_EVIDENCE_PATH.exists()


def _parse_iso_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def _non_empty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _reviewer_count(value: Any) -> int:
    if isinstance(value, str):
        return 1 if value.strip() else 0
    if isinstance(value, dict):
        return 1 if any(_non_empty_text(item) for item in value.values()) else 0
    if isinstance(value, list):
        count = 0
        for item in value:
            if isinstance(item, str) and item.strip():
                count += 1
            elif isinstance(item, dict) and any(_non_empty_text(field) for field in item.values()):
                count += 1
        return count
    return 0


def _category_items(control_evidence: Any, category: str) -> list[dict[str, Any]]:
    if not isinstance(control_evidence, dict):
        return []
    value = control_evidence.get(category)
    if isinstance(value, dict):
        nested = value.get("items")
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _has_reference(item: dict[str, Any]) -> bool:
    return any(_non_empty_text(item.get(field)) for field in ("ref", "uri", "url", "ticket", "artifact_id", "path"))


def _has_integrity(item: dict[str, Any]) -> bool:
    sha256 = item.get("sha256") or item.get("checksum_sha256")
    if isinstance(sha256, str) and SHA256_RE.fullmatch(sha256.strip()):
        return True
    return item.get("immutable") is True or item.get("signed") is True


def _secret_markers(value: Any, path: str = "$", markers: list[str] | None = None) -> list[str]:
    markers = markers if markers is not None else []
    if len(markers) >= 10:
        return markers
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            child_path = f"{path}.{key_text}"
            if key_lower in {"password", "secret", "api_key", "access_token", "refresh_token", "private_key"}:
                if isinstance(child, str) and child.strip() and child.strip().lower() not in {"redacted", "***", "<redacted>"}:
                    markers.append(child_path)
            _secret_markers(child, child_path, markers)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _secret_markers(child, f"{path}[{index}]", markers)
    elif isinstance(value, str) and INLINE_SECRET_RE.search(value):
        markers.append(path)
    return markers


def security_review_evidence_report(path: str | Path | None = None) -> dict[str, Any]:
    evidence_path, configured = _resolve_evidence_path(path)
    base: dict[str, Any] = {
        "configured": configured,
        "path": str(evidence_path),
        "required_categories": list(REQUIRED_EVIDENCE_CATEGORIES),
    }
    if not configured:
        return {
            **base,
            "ok": False,
            "issues": [
                f"Set {SECURITY_REVIEW_EVIDENCE_ENV} or create {DEFAULT_SECURITY_REVIEW_EVIDENCE_PATH.relative_to(PROJECT_ROOT)}."
            ],
        }
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {**base, "ok": False, "issues": [str(exc)]}
    if not isinstance(payload, dict):
        return {**base, "ok": False, "issues": ["Evidence file must contain a JSON object."]}

    issues: list[str] = []
    status = str(payload.get("status") or "").strip().lower()
    if status not in APPROVED_REVIEW_STATUSES:
        issues.append("status must be one of approved, accepted, passed or pass")
    if not _non_empty_text(payload.get("review_id")):
        issues.append("review_id is required")
    approved_at = _parse_iso_date(payload.get("approved_at"))
    if approved_at is None:
        issues.append("approved_at must be an ISO date")
    expires_at = _parse_iso_date(payload.get("expires_at"))
    if expires_at is None:
        issues.append("expires_at must be an ISO date")
    elif expires_at < date.today():
        issues.append("expires_at is in the past")
    reviewer_count = _reviewer_count(payload.get("approved_by") or payload.get("reviewers"))
    if reviewer_count == 0:
        issues.append("approved_by or reviewers must contain at least one reviewer")
    scope = payload.get("scope")
    if not isinstance(scope, dict) or not _non_empty_text(scope.get("environment")):
        issues.append("scope.environment is required")
    if payload.get("redacted") is not True and payload.get("contains_sensitive_values") is not False:
        issues.append("evidence metadata must declare redacted=true or contains_sensitive_values=false")

    control_evidence = payload.get("control_evidence")
    category_summary: dict[str, dict[str, int]] = {}
    for category in REQUIRED_EVIDENCE_CATEGORIES:
        items = _category_items(control_evidence, category)
        complete = sum(1 for item in items if _has_reference(item) and _has_integrity(item))
        category_summary[category] = {"items": len(items), "complete": complete}
        if complete == 0:
            issues.append(f"control_evidence.{category} needs at least one ref plus sha256/immutable/signed marker")

    secret_markers = _secret_markers(payload)
    if secret_markers:
        issues.append("evidence metadata appears to contain raw secret values")

    return {
        **base,
        "ok": not issues,
        "review_id": payload.get("review_id"),
        "status": status,
        "approved_at": payload.get("approved_at"),
        "expires_at": payload.get("expires_at"),
        "reviewer_count": reviewer_count,
        "scope": {key: scope.get(key) for key in sorted(scope)} if isinstance(scope, dict) else {},
        "categories": category_summary,
        "secret_marker_count": len(secret_markers),
        "secret_marker_paths": secret_markers,
        "issues": issues,
    }
