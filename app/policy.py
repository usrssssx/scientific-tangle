from __future__ import annotations

import json
import os
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from .config import ROLE_ORDER
from .security import AccessContext, normalize_context


class PolicyError(PermissionError):
    pass


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    source: str = "local"
    external: dict[str, Any] | None = None


@dataclass(frozen=True)
class ActionPolicy:
    action: str
    description: str
    min_role: str | None = None
    allowed_roles: frozenset[str] | None = None

    def allows(self, context: AccessContext | str) -> bool:
        ctx = normalize_context(context)
        if self.allowed_roles is not None:
            return ctx.role in self.allowed_roles
        if self.min_role is None:
            return True
        return ctx.role_level >= ROLE_ORDER.get(self.min_role, 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "description": self.description,
            "min_role": self.min_role,
            "allowed_roles": sorted(self.allowed_roles) if self.allowed_roles is not None else None,
        }


ACTION_POLICIES: dict[str, ActionPolicy] = {
    "metrics.read": ActionPolicy("metrics.read", "Read in-process and Prometheus metrics", allowed_roles=frozenset({"admin"})),
    "admin.rebuild_demo": ActionPolicy("admin.rebuild_demo", "Rebuild the local demo database", allowed_roles=frozenset({"admin"})),
    "ingest.upload": ActionPolicy("ingest.upload", "Upload a document or archive through the API", allowed_roles=frozenset({"analyst", "admin"})),
    "ingest.local_folder": ActionPolicy("ingest.local_folder", "Ingest a server-local folder", allowed_roles=frozenset({"admin"})),
    "audit.read": ActionPolicy("audit.read", "Read audit log entries", allowed_roles=frozenset({"admin"})),
    "policy.read": ActionPolicy("policy.read", "Read the centralized action policy matrix", allowed_roles=frozenset({"admin"})),
    "security.review.read": ActionPolicy("security.review.read", "Read internal security review gate results", allowed_roles=frozenset({"admin"})),
    "storage.encryption.read": ActionPolicy("storage.encryption.read", "Read storage encryption readiness and at-rest protection status", allowed_roles=frozenset({"admin"})),
    "directory.read": ActionPolicy("directory.read", "Read SCIM directory users, groups, and service metadata", allowed_roles=frozenset({"admin"})),
    "directory.write": ActionPolicy("directory.write", "Provision, update, deactivate, or delete SCIM directory users and groups", allowed_roles=frozenset({"admin"})),
    "export.approval.request": ActionPolicy("export.approval.request", "Request an approval for a blocked sensitive export", allowed_roles=frozenset({"researcher", "analyst", "manager", "admin"})),
    "export.approval.review": ActionPolicy("export.approval.review", "List, approve, or reject sensitive export approvals", allowed_roles=frozenset({"admin"})),
    "curation.read": ActionPolicy("curation.read", "Read curation queues, disputes, and fact history", allowed_roles=frozenset({"analyst", "admin"})),
    "curation.write": ActionPolicy("curation.write", "Assign, review, supersede, dispute, merge, or split curated knowledge", allowed_roles=frozenset({"analyst", "admin"})),
}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def external_policy_enabled() -> bool:
    return bool(os.getenv("RD_KG_POLICY_ENGINE_URL", "").strip())


def _env_or_file(name: str, file_name: str) -> str | None:
    value = os.getenv(name)
    if value:
        return value
    path = os.getenv(file_name)
    if not path:
        return None
    try:
        return open(path, encoding="utf-8").read().strip()
    except OSError as exc:
        raise PolicyError(f"{file_name} cannot be read") from exc


def _policy_engine_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    bearer = _env_or_file("RD_KG_POLICY_ENGINE_BEARER_TOKEN", "RD_KG_POLICY_ENGINE_BEARER_TOKEN_FILE")
    if bearer:
        headers[os.getenv("RD_KG_POLICY_ENGINE_AUTH_HEADER", "Authorization") or "Authorization"] = f"Bearer {bearer}"
    custom_headers = os.getenv("RD_KG_POLICY_ENGINE_HEADERS_JSON", "").strip()
    if custom_headers:
        try:
            payload = json.loads(custom_headers)
        except json.JSONDecodeError as exc:
            raise PolicyError("RD_KG_POLICY_ENGINE_HEADERS_JSON must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise PolicyError("RD_KG_POLICY_ENGINE_HEADERS_JSON must be a JSON object")
        for key, value in payload.items():
            if key and value is not None:
                headers[str(key)] = str(value)
    return headers


def _policy_engine_ssl_context() -> ssl.SSLContext | None:
    ca_file = os.getenv("RD_KG_POLICY_ENGINE_CA_FILE")
    cert_file = os.getenv("RD_KG_POLICY_ENGINE_CLIENT_CERT")
    key_file = os.getenv("RD_KG_POLICY_ENGINE_CLIENT_KEY")
    if not any([ca_file, cert_file, key_file]):
        return None
    context = ssl.create_default_context(cafile=ca_file or None)
    if cert_file:
        context.load_cert_chain(certfile=cert_file, keyfile=key_file or None)
    elif key_file:
        raise PolicyError("RD_KG_POLICY_ENGINE_CLIENT_KEY requires RD_KG_POLICY_ENGINE_CLIENT_CERT")
    return context


def _context_payload(context: AccessContext) -> dict[str, Any]:
    return {
        "role": context.role,
        "role_level": context.role_level,
        "department": context.department,
        "project": context.project,
        "clearance": context.clearance,
        "subject": context.subject,
        "auth_method": context.auth_method,
    }


def _parse_external_response(payload: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
    result = payload.get("result", payload)
    if isinstance(result, bool):
        return result, "external policy allowed" if result else "external policy denied", {"result": result}
    if not isinstance(result, dict):
        raise PolicyError("External policy response must be a JSON object, boolean result, or object result")
    raw_allowed = result.get("allow", result.get("allowed"))
    if raw_allowed is None:
        raw_allowed = result.get("decision")
    if isinstance(raw_allowed, str):
        allowed = raw_allowed.strip().lower() in {"allow", "allowed", "true", "1", "yes"}
    else:
        allowed = bool(raw_allowed)
    reason = str(result.get("reason") or result.get("message") or ("external policy allowed" if allowed else "external policy denied"))
    return allowed, reason, result


def _external_policy_decision(
    action: str,
    context: AccessContext,
    *,
    resource: dict[str, Any] | None,
    local_decision: PolicyDecision,
) -> PolicyDecision | None:
    url = os.getenv("RD_KG_POLICY_ENGINE_URL", "").strip()
    if not url:
        return None
    request_body = {
        "input": {
            "action": action,
            "subject": _context_payload(context),
            "resource": resource or {},
            "local_policy": {
                "allowed": local_decision.allowed,
                "reason": local_decision.reason,
            },
        }
    }
    timeout = float(os.getenv("RD_KG_POLICY_ENGINE_TIMEOUT_SECONDS", "2") or 2)
    request = Request(
        url,
        data=json.dumps(request_body, ensure_ascii=False).encode("utf-8"),
        headers=_policy_engine_headers(),
        method="POST",
    )
    try:
        ssl_context = _policy_engine_ssl_context()
        if ssl_context is not None:
            response_context = urlopen(request, timeout=timeout, context=ssl_context)
        else:
            response_context = urlopen(request, timeout=timeout)
        with response_context as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, json.JSONDecodeError) as exc:
        if _env_bool("RD_KG_POLICY_ENGINE_FAIL_OPEN"):
            return PolicyDecision(
                allowed=True,
                reason=f"external policy unavailable; fail-open enabled: {exc}",
                source="external_fail_open",
            )
        return PolicyDecision(
            allowed=False,
            reason=f"external policy unavailable; fail-closed: {exc}",
            source="external",
        )
    if not isinstance(payload, dict):
        raise PolicyError("External policy response must be a JSON object")
    allowed, reason, external = _parse_external_response(payload)
    return PolicyDecision(allowed=allowed, reason=reason, source="external", external=external)


def policy_matrix() -> list[dict[str, Any]]:
    return [policy.as_dict() for _, policy in sorted(ACTION_POLICIES.items())]


def evaluate_action_policy(action: str, context: AccessContext | str, resource: dict[str, Any] | None = None) -> PolicyDecision:
    ctx = normalize_context(context)
    policy = ACTION_POLICIES.get(action)
    if policy is None:
        raise PolicyError(f"Unknown action policy: {action}")
    if not policy.allows(ctx):
        roles = ", ".join(sorted(policy.allowed_roles)) if policy.allowed_roles else f"{policy.min_role}+"
        return PolicyDecision(False, f"Action {action} requires role {roles}", source="local")
    local_decision = PolicyDecision(True, "allowed by local action policy", source="local")
    external_decision = _external_policy_decision(action, ctx, resource=resource, local_decision=local_decision)
    return external_decision or local_decision


def can_perform_action(action: str, context: AccessContext | str, resource: dict[str, Any] | None = None) -> bool:
    return evaluate_action_policy(action, context, resource=resource).allowed


def require_action(action: str, context: AccessContext | str, resource: dict[str, Any] | None = None) -> None:
    decision = evaluate_action_policy(action, context, resource=resource)
    if not decision.allowed:
        raise PolicyError(decision.reason)
