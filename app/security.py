from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Any

from .config import CONFIDENTIALITY_MIN_ROLE, ROLE_ORDER


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", flags=re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)")
DATETIME_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}$")
SECRET_RE = re.compile(r"\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*['\"]?[^'\"\s,;]+", flags=re.IGNORECASE)
SECRET_KEY_RE = re.compile(r"(?:api[_-]?key|token|password|secret)", flags=re.IGNORECASE)
CONFIDENTIALITY_ORDER = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "secret": 3,
}
EXPORT_MIN_ROLE = {
    "public": "external_partner",
    "internal": "researcher",
    "confidential": "analyst",
    "secret": "admin",
}


@dataclass(frozen=True)
class AccessContext:
    role: str
    department: str | None = None
    project: str | None = None
    clearance: str | None = None

    @property
    def role_level(self) -> int:
        return ROLE_ORDER.get(self.role, 0)

    def can_see_direct_identifiers(self) -> bool:
        return self.role in {"admin", "analyst"}

    def can_see_paths(self) -> bool:
        return self.role in {"admin", "analyst"}


@dataclass(frozen=True)
class ExportPolicyDecision:
    allowed: bool
    export_format: str
    role: str
    max_confidentiality: str
    classifications: list[str]
    reason: str

    def audit_details(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "format": self.export_format,
            "role": self.role,
            "max_confidentiality": self.max_confidentiality,
            "classifications": self.classifications,
            "reason": self.reason,
        }


def normalize_context(role: str | AccessContext | None = None, **kwargs: Any) -> AccessContext:
    if isinstance(role, AccessContext):
        return role
    return AccessContext(role=role or "researcher", **kwargs)


def _metadata_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _as_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {part.strip().lower() for part in value.split(",") if part.strip()}
    if isinstance(value, list | tuple | set):
        return {str(part).strip().lower() for part in value if str(part).strip()}
    return {str(value).strip().lower()} if str(value).strip() else set()


def can_access(confidentiality: str | None, context: AccessContext | str) -> bool:
    ctx = normalize_context(context)
    conf = confidentiality or "internal"
    min_role = CONFIDENTIALITY_MIN_ROLE.get(conf, "researcher")
    return ctx.role_level >= ROLE_ORDER.get(min_role, 1)


def can_export_confidentiality(confidentiality: str | None, context: AccessContext | str) -> bool:
    ctx = normalize_context(context)
    conf = confidentiality or "internal"
    min_role = EXPORT_MIN_ROLE.get(conf, CONFIDENTIALITY_MIN_ROLE.get(conf, "researcher"))
    return ctx.role_level >= ROLE_ORDER.get(min_role, 1)


def _classification_rank(value: str) -> int:
    return CONFIDENTIALITY_ORDER.get(value, CONFIDENTIALITY_ORDER["internal"])


def _coerce_classification_values(value: Any) -> set[str]:
    if isinstance(value, str):
        normalized = value.lower()
        return {normalized} if normalized in CONFIDENTIALITY_ORDER else set()
    if isinstance(value, list | tuple | set):
        levels: set[str] = set()
        for item in value:
            levels.update(_coerce_classification_values(item))
        return levels
    if isinstance(value, dict):
        return _extract_classifications(value)
    return set()


def _extract_classifications(obj: Any) -> set[str]:
    levels: set[str] = set()
    if isinstance(obj, str):
        for level in CONFIDENTIALITY_ORDER:
            if f'sourceConfidentiality "{level}"' in obj:
                levels.add(level)
        return levels
    if isinstance(obj, list):
        for item in obj:
            levels.update(_extract_classifications(item))
        return levels
    if not isinstance(obj, dict):
        return levels
    for key, value in obj.items():
        normalized_key = str(key).lower()
        if normalized_key in {"confidentiality", "source_confidentiality", "data_classification"}:
            levels.update(_coerce_classification_values(value))
        if isinstance(value, dict | list):
            levels.update(_extract_classifications(value))
    return levels


def evaluate_export_policy(payload: Any, context: AccessContext | str, export_format: str) -> ExportPolicyDecision:
    ctx = normalize_context(context)
    classifications = sorted(_extract_classifications(payload), key=_classification_rank)
    max_confidentiality = classifications[-1] if classifications else "public"
    if can_export_confidentiality(max_confidentiality, ctx):
        return ExportPolicyDecision(
            allowed=True,
            export_format=export_format,
            role=ctx.role,
            max_confidentiality=max_confidentiality,
            classifications=classifications,
            reason="allowed",
        )
    min_role = EXPORT_MIN_ROLE.get(max_confidentiality, CONFIDENTIALITY_MIN_ROLE.get(max_confidentiality, "researcher"))
    return ExportPolicyDecision(
        allowed=False,
        export_format=export_format,
        role=ctx.role,
        max_confidentiality=max_confidentiality,
        classifications=classifications,
        reason=f"Export of {max_confidentiality} data requires role {min_role}",
    )


def can_access_source(source: dict[str, Any], context: AccessContext | str) -> bool:
    ctx = normalize_context(context)
    if not can_access(source.get("confidentiality"), ctx):
        return False
    if ctx.role == "admin":
        return True
    metadata = _metadata_dict(source.get("metadata") or source.get("metadata_json"))
    allowed_departments = _as_set(metadata.get("allowed_departments") or metadata.get("department"))
    if allowed_departments and (ctx.department or "").lower() not in allowed_departments:
        return False
    allowed_projects = _as_set(metadata.get("allowed_projects") or metadata.get("project"))
    if allowed_projects and (ctx.project or "").lower() not in allowed_projects:
        return False
    min_clearance = metadata.get("min_clearance")
    if min_clearance:
        min_level = ROLE_ORDER.get(str(min_clearance), ROLE_ORDER.get("researcher", 1))
        if ctx.role_level < min_level:
            return False
    return True


def sql_confidentiality_clause(context: AccessContext | str, include_internal: bool = True, alias: str = "s") -> tuple[str, list[Any]]:
    ctx = normalize_context(context)
    allowed = [conf for conf, min_role in CONFIDENTIALITY_MIN_ROLE.items() if ctx.role_level >= ROLE_ORDER.get(min_role, 1)]
    if not include_internal:
        allowed = ["public"] if "public" in allowed else []
    if not allowed:
        return "1=0", []
    return f"{alias}.confidentiality IN ({','.join('?' for _ in allowed)})", allowed


def redact_text(text: str, context: AccessContext | str) -> str:
    ctx = normalize_context(context)
    if not ctx.can_see_direct_identifiers():
        text = EMAIL_RE.sub("[redacted-email]", text)

        def redact_phone(match: re.Match[str]) -> str:
            candidate = match.group(0)
            digits = re.sub(r"\D", "", candidate)
            if len(digits) < 10 or DATETIME_PREFIX_RE.match(candidate):
                return candidate
            return "[redacted-phone]"

        text = PHONE_RE.sub(redact_phone, text)
    text = SECRET_RE.sub("[redacted-secret]", text)
    return text


def dlp_sanitize(obj: Any, context: AccessContext | str, export: bool = False) -> Any:
    ctx = normalize_context(context)
    if isinstance(obj, str):
        return redact_text(obj, ctx)
    if isinstance(obj, list):
        return [dlp_sanitize(item, ctx, export=export) for item in obj]
    if not isinstance(obj, dict):
        return obj
    result: dict[str, Any] = {}
    for key, value in copy.deepcopy(obj).items():
        if SECRET_KEY_RE.search(str(key)):
            result[key] = "[redacted-secret]"
            continue
        if key in {"path", "db_path"} and not ctx.can_see_paths():
            result[key] = "[redacted-path]"
            continue
        if key in {"contact", "email", "phone"} and not ctx.can_see_direct_identifiers():
            result[key] = "[redacted-contact]"
            continue
        if export and key in {"abstract"} and not ctx.can_see_direct_identifiers():
            result[key] = redact_text(str(value), ctx)[:300]
            continue
        result[key] = dlp_sanitize(value, ctx, export=export)
    return result


def safe_audit_details(details: dict[str, Any] | None, context: AccessContext | str) -> dict[str, Any]:
    if not details:
        return {}
    return dlp_sanitize(details, context, export=True)
