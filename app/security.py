from __future__ import annotations

import copy
import base64
import hmac
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .config import CONFIDENTIALITY_MIN_ROLE, ROLE_ORDER
from .dlp import inspect_export_payload


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
_JWKS_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


@dataclass(frozen=True)
class AccessContext:
    role: str
    department: str | None = None
    project: str | None = None
    clearance: str | None = None
    subject: str | None = None
    auth_method: str = "headers"

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
    dlp_findings: list[dict[str, Any]] | None = None

    def audit_details(self) -> dict[str, Any]:
        details = {
            "allowed": self.allowed,
            "format": self.export_format,
            "role": self.role,
            "max_confidentiality": self.max_confidentiality,
            "classifications": self.classifications,
            "reason": self.reason,
        }
        if self.dlp_findings:
            details["dlp_findings"] = self.dlp_findings
        return details


class AuthError(ValueError):
    pass


def normalize_context(role: str | AccessContext | None = None, **kwargs: Any) -> AccessContext:
    if isinstance(role, AccessContext):
        return role
    return AccessContext(role=role or "researcher", **kwargs)


def oidc_required() -> bool:
    return os.getenv("RD_KG_OIDC_REQUIRED", "").strip().lower() in {"1", "true", "yes", "on"}


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    return value if value not in {None, ""} else default


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - normalize auth error
        raise AuthError("Invalid JWT base64 encoding") from exc


def _jwt_json(value: str) -> dict[str, Any]:
    try:
        payload = json.loads(_b64url_decode(value).decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise AuthError("Invalid JWT JSON") from exc
    if not isinstance(payload, dict):
        raise AuthError("Invalid JWT payload")
    return payload


def _jwt_parts(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("Bearer token must be a compact JWT")
    return parts[0], parts[1], parts[2]


def _validate_registered_claims(claims: dict[str, Any]) -> None:
    now = time.time()
    skew = float(_env("RD_KG_OIDC_CLOCK_SKEW_SECONDS", "60") or 60)
    if claims.get("exp") is not None and float(claims["exp"]) < now - skew:
        raise AuthError("JWT is expired")
    if claims.get("nbf") is not None and float(claims["nbf"]) > now + skew:
        raise AuthError("JWT is not yet valid")
    if claims.get("iat") is not None and float(claims["iat"]) > now + skew:
        raise AuthError("JWT issued-at is in the future")
    issuer = _env("RD_KG_OIDC_ISSUER")
    if issuer and claims.get("iss") != issuer:
        raise AuthError("JWT issuer mismatch")
    audience = _env("RD_KG_OIDC_AUDIENCE")
    if audience:
        token_audience = claims.get("aud")
        audiences = token_audience if isinstance(token_audience, list) else [token_audience]
        if audience not in audiences:
            raise AuthError("JWT audience mismatch")


def _validate_hs256_jwt(token: str, header: dict[str, Any]) -> dict[str, Any]:
    head, body, signature = _jwt_parts(token)
    if header.get("alg") != "HS256":
        raise AuthError("Only HS256 JWT validation is enabled for local OIDC mode")
    secret = _env("RD_KG_OIDC_HS256_SECRET")
    if not secret:
        raise AuthError("RD_KG_OIDC_HS256_SECRET is required for JWT authentication")
    signed = f"{head}.{body}".encode("ascii")
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).digest()
    received = _b64url_decode(signature)
    if not hmac.compare_digest(expected, received):
        raise AuthError("Invalid JWT signature")
    claims = _jwt_json(body)
    _validate_registered_claims(claims)
    return claims


def _json_from_url(url: str) -> dict[str, Any]:
    request = Request(url, headers={"Accept": "application/json"})
    timeout = float(_env("RD_KG_OIDC_HTTP_TIMEOUT_SECONDS", "5") or 5)
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, json.JSONDecodeError) as exc:
        raise AuthError(f"OIDC metadata fetch failed: {url}") from exc
    if not isinstance(payload, dict):
        raise AuthError("OIDC metadata response must be a JSON object")
    return payload


def _cached_json(url: str) -> dict[str, Any]:
    now = time.time()
    ttl = float(_env("RD_KG_OIDC_JWKS_CACHE_TTL_SECONDS", "300") or 300)
    cached = _JWKS_CACHE.get(url)
    if cached and cached[0] > now:
        return cached[1]
    payload = _json_from_url(url)
    _JWKS_CACHE[url] = (now + ttl, payload)
    return payload


def _discover_jwks_uri() -> str | None:
    discovery_url = _env("RD_KG_OIDC_DISCOVERY_URL")
    issuer = _env("RD_KG_OIDC_ISSUER")
    if not discovery_url and issuer:
        discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    if not discovery_url:
        return None
    metadata = _cached_json(discovery_url)
    jwks_uri = metadata.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise AuthError("OIDC discovery metadata does not include jwks_uri")
    return jwks_uri


def _load_jwks() -> dict[str, Any]:
    inline_jwks = _env("RD_KG_OIDC_JWKS_JSON")
    if inline_jwks:
        try:
            jwks = json.loads(inline_jwks)
        except json.JSONDecodeError as exc:
            raise AuthError("RD_KG_OIDC_JWKS_JSON must be valid JSON") from exc
        if not isinstance(jwks, dict):
            raise AuthError("RD_KG_OIDC_JWKS_JSON must be a JWKS object")
        return jwks
    jwks_url = _env("RD_KG_OIDC_JWKS_URL") or _discover_jwks_uri()
    if not jwks_url:
        raise AuthError("RS256 JWT validation requires RD_KG_OIDC_JWKS_URL or OIDC discovery")
    return _cached_json(jwks_url)


def _select_jwk(header: dict[str, Any], jwks: dict[str, Any]) -> dict[str, Any]:
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise AuthError("JWKS does not contain signing keys")
    kid = header.get("kid")
    candidates = [
        key
        for key in keys
        if isinstance(key, dict)
        and key.get("kty") == "RSA"
        and key.get("alg", "RS256") == "RS256"
        and key.get("use", "sig") == "sig"
    ]
    if kid:
        for key in candidates:
            if key.get("kid") == kid:
                return key
        raise AuthError("JWT key id was not found in JWKS")
    if len(candidates) == 1:
        return candidates[0]
    raise AuthError("JWT header must include kid when JWKS has multiple RSA signing keys")


def _jwk_int(value: Any, field: str) -> int:
    if not isinstance(value, str) or not value:
        raise AuthError(f"JWKS RSA key is missing {field}")
    return int.from_bytes(_b64url_decode(value), byteorder="big")


def _rsa_public_key(jwk: dict[str, Any]) -> rsa.RSAPublicKey:
    public_numbers = rsa.RSAPublicNumbers(
        e=_jwk_int(jwk.get("e"), "e"),
        n=_jwk_int(jwk.get("n"), "n"),
    )
    try:
        return public_numbers.public_key()
    except ValueError as exc:
        raise AuthError("Invalid RSA public key in JWKS") from exc


def _validate_rs256_jwt(token: str, header: dict[str, Any]) -> dict[str, Any]:
    head, body, signature = _jwt_parts(token)
    jwk = _select_jwk(header, _load_jwks())
    public_key = _rsa_public_key(jwk)
    try:
        public_key.verify(
            _b64url_decode(signature),
            f"{head}.{body}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise AuthError("Invalid JWT signature") from exc
    claims = _jwt_json(body)
    _validate_registered_claims(claims)
    return claims


def _validate_oidc_jwt(token: str) -> dict[str, Any]:
    head, _, _ = _jwt_parts(token)
    header = _jwt_json(head)
    alg = header.get("alg")
    if alg == "HS256":
        return _validate_hs256_jwt(token, header)
    if alg == "RS256":
        return _validate_rs256_jwt(token, header)
    raise AuthError(f"Unsupported JWT alg: {alg}")


def _claim_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple | set):
        return [str(item) for item in value]
    return []


def _append_role(roles: list[str], candidate: str) -> None:
    normalized = candidate.strip()
    if normalized in ROLE_ORDER and normalized not in roles:
        roles.append(normalized)


def _load_group_role_map() -> dict[str, str]:
    payloads: list[Any] = []
    map_file = _env("RD_KG_OIDC_GROUP_ROLE_MAP_FILE")
    if map_file:
        try:
            payloads.append(json.loads(Path(map_file).read_text(encoding="utf-8")))
        except OSError as exc:
            raise AuthError("RD_KG_OIDC_GROUP_ROLE_MAP_FILE cannot be read") from exc
        except json.JSONDecodeError as exc:
            raise AuthError("RD_KG_OIDC_GROUP_ROLE_MAP_FILE must contain a JSON object") from exc
    inline_map = _env("RD_KG_OIDC_GROUP_ROLE_MAP_JSON")
    if inline_map:
        try:
            payloads.append(json.loads(inline_map))
        except json.JSONDecodeError as exc:
            raise AuthError("RD_KG_OIDC_GROUP_ROLE_MAP_JSON must be valid JSON") from exc

    mapping: dict[str, str] = {}
    for payload in payloads:
        if not isinstance(payload, dict):
            raise AuthError("OIDC group role map must be a JSON object")
        for raw_group, raw_role in payload.items():
            group = str(raw_group).strip()
            role = str(raw_role).strip()
            if group and role in ROLE_ORDER:
                mapping[group.casefold()] = role
    return mapping


def _group_aliases(group: str) -> set[str]:
    value = group.strip()
    if not value:
        return set()
    aliases = {value}
    for separator in ("/", "\\"):
        if separator in value:
            tail = value.rsplit(separator, 1)[-1].strip()
            if tail:
                aliases.add(tail)
    cn_match = re.search(r"(?:^|,)\s*CN=([^,]+)", value, flags=re.IGNORECASE)
    if cn_match:
        aliases.add(cn_match.group(1).strip())
    return {alias.casefold() for alias in aliases if alias.strip()}


def _mapped_group_roles(group_claims: list[str]) -> list[str]:
    group_map = _load_group_role_map()
    if not group_map:
        return []
    roles: list[str] = []
    for group in group_claims:
        for alias in _group_aliases(group):
            role = group_map.get(alias)
            if role:
                _append_role(roles, role)
    return roles


def _roles_from_claims(claims: dict[str, Any]) -> list[str]:
    role_claim = _env("RD_KG_OIDC_ROLE_CLAIM", "role") or "role"
    group_claim = _env("RD_KG_OIDC_GROUP_CLAIM", "groups") or "groups"
    role_values: list[Any] = []
    if role_claim in claims:
        role_values.append(claims.get(role_claim))
    role_values.append(claims.get("roles"))
    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        role_values.append(realm_access.get("roles"))

    group_values: list[Any] = []
    if group_claim in claims:
        group_values.append(claims.get(group_claim))
    if group_claim != "groups":
        group_values.append(claims.get("groups"))
    group_values.append(claims.get("memberOf"))

    roles: list[str] = []
    for value in role_values + group_values:
        for candidate in _claim_strings(value):
            _append_role(roles, candidate)
    group_claims = [candidate for value in group_values for candidate in _claim_strings(value)]
    for role in _mapped_group_roles(group_claims):
        _append_role(roles, role)
    return roles


def _highest_role(roles: list[str], default_role: str) -> str:
    if not roles:
        return default_role if default_role in ROLE_ORDER else "researcher"
    return max(roles, key=lambda role: ROLE_ORDER.get(role, 0))


def access_context_from_authorization(
    authorization: str | None,
    *,
    default_role: str = "researcher",
    header_role: str | None = None,
    header_department: str | None = None,
    header_project: str | None = None,
    header_clearance: str | None = None,
    header_subject: str | None = None,
) -> AccessContext:
    token: str | None = None
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not value:
            raise AuthError("Authorization header must be Bearer JWT")
        token = value.strip()
    if not token:
        if oidc_required():
            raise AuthError("Bearer JWT is required")
        return AccessContext(
            role=header_role or default_role,
            department=header_department,
            project=header_project,
            clearance=header_clearance,
            subject=header_subject,
            auth_method="headers",
        )
    claims = _validate_oidc_jwt(token)
    role = _highest_role(_roles_from_claims(claims), default_role)
    department_claim = _env("RD_KG_OIDC_DEPARTMENT_CLAIM", "department") or "department"
    project_claim = _env("RD_KG_OIDC_PROJECT_CLAIM", "project") or "project"
    clearance_claim = _env("RD_KG_OIDC_CLEARANCE_CLAIM", "clearance") or "clearance"
    return AccessContext(
        role=role,
        department=claims.get(department_claim),
        project=claims.get(project_claim),
        clearance=claims.get(clearance_claim),
        subject=claims.get("sub"),
        auth_method="jwt",
    )


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
    dlp_findings = inspect_export_payload(payload, export_format)
    for finding in dlp_findings:
        classification = str(finding.get("classification") or "")
        action = str(finding.get("action") or "")
        if action in {"approval_required", "block"} and classification in CONFIDENTIALITY_ORDER:
            classifications.append(classification)
    classifications = sorted(set(classifications), key=_classification_rank)
    max_confidentiality = classifications[-1] if classifications else "public"
    if can_export_confidentiality(max_confidentiality, ctx):
        blocking_findings = [item for item in dlp_findings if item.get("action") == "block"]
        if blocking_findings:
            return ExportPolicyDecision(
                allowed=False,
                export_format=export_format,
                role=ctx.role,
                max_confidentiality=max_confidentiality,
                classifications=classifications,
                reason="DLP content inspection blocked export",
                dlp_findings=dlp_findings,
            )
        return ExportPolicyDecision(
            allowed=True,
            export_format=export_format,
            role=ctx.role,
            max_confidentiality=max_confidentiality,
            classifications=classifications,
            reason="allowed",
            dlp_findings=dlp_findings,
        )
    min_role = EXPORT_MIN_ROLE.get(max_confidentiality, CONFIDENTIALITY_MIN_ROLE.get(max_confidentiality, "researcher"))
    dlp_required = [item["rule"] for item in dlp_findings if item.get("action") in {"approval_required", "block"}]
    reason = f"Export of {max_confidentiality} data requires role {min_role}"
    if dlp_required:
        reason = f"{reason}; DLP content inspection matched: {', '.join(dlp_required)}"
    return ExportPolicyDecision(
        allowed=False,
        export_format=export_format,
        role=ctx.role,
        max_confidentiality=max_confidentiality,
        classifications=classifications,
        reason=reason,
        dlp_findings=dlp_findings,
    )


def export_payload_hash(payload: Any) -> str:
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


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
