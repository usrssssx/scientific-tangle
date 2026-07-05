from __future__ import annotations

import os
from typing import Any

from .config import ROLE_ORDER
from .db import get_directory_user, list_directory_user_groups
from .security import AccessContext

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_BULK_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
SCIM_BULK_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
SCIM_ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
RDKG_SECURITY_USER_SCHEMA = "urn:rdkg:params:scim:schemas:extension:security:2.0:User"
SCIM_BULK_MAX_OPERATIONS = 100
SCIM_BULK_MAX_PAYLOAD_SIZE = 1_048_576


class DirectoryAccessError(PermissionError):
    def __init__(self, message: str, *, status_code: int = 403):
        super().__init__(message)
        self.status_code = status_code


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def directory_required() -> bool:
    return _env_bool("RD_KG_DIRECTORY_REQUIRED")


def _bool_value(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off", "inactive", "disabled"}
    return bool(value)


def _valid_role(value: Any) -> str | None:
    if value in {None, ""}:
        return None
    role = str(value).strip()
    return role if role in ROLE_ORDER else None


def _highest_role(roles: list[str]) -> str | None:
    valid_roles = [role for role in roles if role in ROLE_ORDER]
    if not valid_roles:
        return None
    return max(valid_roles, key=lambda role: ROLE_ORDER.get(role, 0))


def apply_directory_context(conn, context: AccessContext) -> AccessContext:
    if not directory_required():
        return context
    if not context.subject:
        raise DirectoryAccessError("Directory subject is required", status_code=401)
    user = get_directory_user(conn, context.subject)
    if user is None:
        raise DirectoryAccessError("Directory user is not provisioned")
    if not _bool_value(user.get("active")):
        raise DirectoryAccessError("Directory user is disabled")

    groups = list_directory_user_groups(conn, str(user["id"]))
    directory_roles = [_valid_role(user.get("role"))] + [_valid_role(group.get("role")) for group in groups]
    directory_role = _highest_role([role for role in directory_roles if role])
    auth_method = context.auth_method if context.auth_method.endswith("+directory") else f"{context.auth_method}+directory"
    return AccessContext(
        role=directory_role or context.role,
        department=user.get("department") or context.department,
        project=user.get("project") or context.project,
        clearance=user.get("clearance") or context.clearance,
        subject=context.subject,
        auth_method=auth_method,
    )


def _first_role_from_roles(value: Any) -> str | None:
    if isinstance(value, str):
        return _valid_role(value)
    if isinstance(value, dict):
        return _valid_role(value.get("value") or value.get("display") or value.get("role"))
    if isinstance(value, list | tuple):
        for item in value:
            role = _first_role_from_roles(item)
            if role:
                return role
    return None


def _extract_role(payload: dict[str, Any], existing: dict[str, Any] | None = None) -> str | None:
    role = _valid_role(payload.get("role") or payload.get("rdkgRole"))
    if role:
        return role
    role = _first_role_from_roles(payload.get("roles"))
    if role:
        return role
    security_ext = payload.get(RDKG_SECURITY_USER_SCHEMA)
    if isinstance(security_ext, dict):
        role = _valid_role(security_ext.get("role"))
        if role:
            return role
    return _valid_role((existing or {}).get("role"))


def _extension_dict(payload: dict[str, Any], schema: str) -> dict[str, Any]:
    value = payload.get(schema)
    return value if isinstance(value, dict) else {}


def _emails(payload: dict[str, Any], existing: dict[str, Any] | None = None) -> list[Any]:
    value = payload.get("emails")
    if isinstance(value, list):
        return value
    return list((existing or {}).get("emails") or [])


def parse_scim_user_payload(
    payload: dict[str, Any],
    *,
    fallback_id: str | None = None,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    enterprise = _extension_dict(payload, SCIM_ENTERPRISE_USER_SCHEMA)
    security = _extension_dict(payload, RDKG_SECURITY_USER_SCHEMA)
    user_id = str(
        payload.get("id")
        or fallback_id
        or (existing or {}).get("id")
        or payload.get("externalId")
        or payload.get("userName")
        or ""
    ).strip()
    user_name = str(payload.get("userName") or (existing or {}).get("user_name") or user_id).strip()
    if not user_id:
        raise ValueError("SCIM user id, externalId, or userName is required")
    if not user_name:
        raise ValueError("SCIM userName is required")
    active_default = _bool_value((existing or {}).get("active")) if existing else True
    return {
        "user_id": user_id,
        "user_name": user_name,
        "display_name": payload.get("displayName") if "displayName" in payload else (existing or {}).get("display_name"),
        "role": _extract_role(payload, existing),
        "department": payload.get("department") or enterprise.get("department") or (existing or {}).get("department"),
        "project": payload.get("project") or security.get("project") or (existing or {}).get("project"),
        "clearance": payload.get("clearance") or security.get("clearance") or (existing or {}).get("clearance"),
        "active": _bool_value(payload.get("active"), default=active_default),
        "external_id": payload.get("externalId") if "externalId" in payload else (existing or {}).get("external_id"),
        "emails": _emails(payload, existing),
        "metadata": {
            "schemas": payload.get("schemas") or [SCIM_USER_SCHEMA],
            "source": "scim",
        },
    }


def _base_user_payload(existing: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "id": existing.get("id"),
        "userName": existing.get("user_name"),
        "displayName": existing.get("display_name"),
        "active": _bool_value(existing.get("active")),
        "externalId": existing.get("external_id"),
        "emails": existing.get("emails") or [],
        "roles": [{"value": existing.get("role"), "primary": True}] if existing.get("role") else [],
        SCIM_ENTERPRISE_USER_SCHEMA: {"department": existing.get("department")},
        RDKG_SECURITY_USER_SCHEMA: {
            "role": existing.get("role"),
            "project": existing.get("project"),
            "clearance": existing.get("clearance"),
        },
    }
    return payload


def _apply_path(payload: dict[str, Any], path: str, value: Any) -> None:
    normalized = path.strip()
    lowered = normalized.lower()
    if lowered in {"username", "displayname", "active", "externalid", "emails", "roles"}:
        key = {
            "username": "userName",
            "displayname": "displayName",
            "active": "active",
            "externalid": "externalId",
            "emails": "emails",
            "roles": "roles",
        }[lowered]
        payload[key] = value
        return
    if lowered in {"role", "rdkgrole"}:
        payload["role"] = value
        return
    if lowered == "department":
        payload["department"] = value
        return
    if lowered in {"project", "clearance"}:
        payload[lowered] = value
        return
    if normalized.startswith(f"{SCIM_ENTERPRISE_USER_SCHEMA}:"):
        child = normalized[len(SCIM_ENTERPRISE_USER_SCHEMA) + 1 :]
        payload.setdefault(SCIM_ENTERPRISE_USER_SCHEMA, {})[child] = value
        return
    if normalized.startswith(f"{RDKG_SECURITY_USER_SCHEMA}:"):
        child = normalized[len(RDKG_SECURITY_USER_SCHEMA) + 1 :]
        payload.setdefault(RDKG_SECURITY_USER_SCHEMA, {})[child] = value


def apply_scim_user_patch(existing: dict[str, Any], patch_payload: dict[str, Any]) -> dict[str, Any]:
    payload = _base_user_payload(existing)
    operations = patch_payload.get("Operations") or patch_payload.get("operations") or []
    if not isinstance(operations, list):
        raise ValueError("SCIM PATCH Operations must be a list")
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        op = str(operation.get("op") or "replace").lower()
        path = operation.get("path")
        value = operation.get("value")
        if op not in {"add", "replace", "remove"}:
            raise ValueError(f"Unsupported SCIM PATCH op: {op}")
        if op == "remove":
            if path:
                _apply_path(payload, str(path), None)
            continue
        if path:
            _apply_path(payload, str(path), value)
        elif isinstance(value, dict):
            for key, item in value.items():
                _apply_path(payload, str(key), item)
    return parse_scim_user_payload(payload, fallback_id=str(existing["id"]), existing=existing)


def parse_scim_group_payload(
    payload: dict[str, Any],
    *,
    fallback_id: str | None = None,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    group_id = str(
        payload.get("id")
        or fallback_id
        or (existing or {}).get("id")
        or payload.get("externalId")
        or payload.get("displayName")
        or ""
    ).strip()
    display_name = str(payload.get("displayName") or (existing or {}).get("display_name") or group_id).strip()
    if not group_id:
        raise ValueError("SCIM group id, externalId, or displayName is required")
    if not display_name:
        raise ValueError("SCIM group displayName is required")
    return {
        "group_id": group_id,
        "display_name": display_name,
        "role": _extract_role(payload, existing),
        "external_id": payload.get("externalId") if "externalId" in payload else (existing or {}).get("external_id"),
        "metadata": {
            "schemas": payload.get("schemas") or [SCIM_GROUP_SCHEMA],
            "source": "scim",
        },
    }


def member_ids_from_group_payload(payload: dict[str, Any]) -> list[str] | None:
    if "members" not in payload:
        return None
    members = payload.get("members")
    if not isinstance(members, list):
        raise ValueError("SCIM group members must be a list")
    ids: list[str] = []
    for member in members:
        if isinstance(member, dict):
            value = member.get("value") or member.get("id")
        else:
            value = member
        if value not in {None, ""}:
            ids.append(str(value))
    return ids


def apply_scim_group_patch(existing: dict[str, Any], patch_payload: dict[str, Any]) -> tuple[dict[str, Any], list[str] | None]:
    payload = {
        "id": existing.get("id"),
        "displayName": existing.get("display_name"),
        "externalId": existing.get("external_id"),
        "roles": [{"value": existing.get("role"), "primary": True}] if existing.get("role") else [],
    }
    members: list[str] | None = None
    operations = patch_payload.get("Operations") or patch_payload.get("operations") or []
    if not isinstance(operations, list):
        raise ValueError("SCIM PATCH Operations must be a list")
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        op = str(operation.get("op") or "replace").lower()
        path = operation.get("path")
        value = operation.get("value")
        if op not in {"add", "replace", "remove"}:
            raise ValueError(f"Unsupported SCIM PATCH op: {op}")
        if op == "remove":
            if path and str(path).lower() == "members":
                members = []
            continue
        if path and str(path).lower() == "members":
            payload["members"] = value
            members = member_ids_from_group_payload(payload)
        elif path:
            _apply_path(payload, str(path), value)
        elif isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() == "members":
                    payload["members"] = item
                    members = member_ids_from_group_payload(payload)
                else:
                    _apply_path(payload, str(key), item)
    return parse_scim_group_payload(payload, fallback_id=str(existing["id"]), existing=existing), members


def scim_user_resource(user: dict[str, Any], groups: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    group_items = [
        {
            "value": group.get("id"),
            "display": group.get("display_name"),
            "$ref": f"/scim/v2/Groups/{group.get('id')}",
        }
        for group in (groups or [])
    ]
    return {
        "schemas": [SCIM_USER_SCHEMA, SCIM_ENTERPRISE_USER_SCHEMA, RDKG_SECURITY_USER_SCHEMA],
        "id": user.get("id"),
        "externalId": user.get("external_id"),
        "userName": user.get("user_name"),
        "displayName": user.get("display_name"),
        "active": _bool_value(user.get("active")),
        "emails": user.get("emails") or [],
        "roles": [{"value": user.get("role"), "primary": True}] if user.get("role") else [],
        "groups": group_items,
        SCIM_ENTERPRISE_USER_SCHEMA: {"department": user.get("department")},
        RDKG_SECURITY_USER_SCHEMA: {
            "role": user.get("role"),
            "project": user.get("project"),
            "clearance": user.get("clearance"),
        },
        "meta": {"resourceType": "User"},
    }


def scim_group_resource(group: dict[str, Any], members: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    member_items = [
        {
            "value": member.get("id"),
            "display": member.get("user_name"),
            "$ref": f"/scim/v2/Users/{member.get('id')}",
        }
        for member in (members or [])
    ]
    return {
        "schemas": [SCIM_GROUP_SCHEMA],
        "id": group.get("id"),
        "externalId": group.get("external_id"),
        "displayName": group.get("display_name"),
        "roles": [{"value": group.get("role"), "primary": True}] if group.get("role") else [],
        "members": member_items,
        "meta": {"resourceType": "Group"},
    }


def scim_list_response(resources: list[dict[str, Any]], *, total_results: int, start_index: int = 1) -> dict[str, Any]:
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total_results,
        "startIndex": max(1, int(start_index)),
        "itemsPerPage": len(resources),
        "Resources": resources,
    }
