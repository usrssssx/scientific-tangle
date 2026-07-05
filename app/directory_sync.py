from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, ROLE_ORDER
from .db import (
    count_directory_groups,
    count_directory_users,
    deactivate_directory_user,
    delete_directory_group,
    get_directory_group,
    get_directory_user,
    insert_audit,
    list_directory_groups,
    list_directory_users,
    replace_directory_group_members,
    upsert_directory_group,
    upsert_directory_user,
)

DIRECTORY_SYNC_CONFIG_ENV = "RD_KG_DIRECTORY_SYNC_CONFIG"
DEFAULT_DIRECTORY_SYNC_CONFIG_PATH = PROJECT_ROOT / "ops/directory_sync.json"
SUPPORTED_DIRECTORY_SOURCES = {"ldap", "ad", "json"}


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.hex()
    text = str(value).strip()
    return text or None


def _first(value: Any) -> Any:
    if isinstance(value, list | tuple | set):
        return next((item for item in value if item not in {None, ""}), None)
    return value


def _bool_value(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off", "disabled", "inactive"}
    return bool(value)


def _role(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        for item in value:
            role = _role(item)
            if role:
                return role
        return None
    if isinstance(value, dict):
        value = value.get("value") or value.get("role") or value.get("display")
    if value == "":
        return None
    role = str(value).strip()
    return role if role in ROLE_ORDER else None


def _load_json(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON payload must be an object")
    return payload


def load_directory_sync_config(path: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(path or os.getenv(DIRECTORY_SYNC_CONFIG_ENV, "") or DEFAULT_DIRECTORY_SYNC_CONFIG_PATH).expanduser()
    payload = _load_json(config_path)
    payload["_path"] = str(config_path)
    return payload


def _secret_configured(config: dict[str, Any]) -> bool:
    if config.get("bind_password_env"):
        return bool(os.getenv(str(config["bind_password_env"]), "").strip())
    if config.get("bind_password_file"):
        return Path(str(config["bind_password_file"])).expanduser().exists()
    return bool(config.get("anonymous_bind"))


def _config_path(path: str | Path | None = None) -> tuple[Path, bool]:
    if path is not None:
        return Path(path).expanduser(), True
    env_path = os.getenv(DIRECTORY_SYNC_CONFIG_ENV, "").strip()
    if env_path:
        return Path(env_path).expanduser(), True
    return DEFAULT_DIRECTORY_SYNC_CONFIG_PATH, DEFAULT_DIRECTORY_SYNC_CONFIG_PATH.exists()


def directory_sync_config_report(path: str | Path | None = None) -> dict[str, Any]:
    config_path, configured = _config_path(path)
    base = {"configured": configured, "path": str(config_path)}
    if not configured:
        return {
            **base,
            "ok": False,
            "issues": [f"Set {DIRECTORY_SYNC_CONFIG_ENV} or create {DEFAULT_DIRECTORY_SYNC_CONFIG_PATH.relative_to(PROJECT_ROOT)}."],
        }
    try:
        config = load_directory_sync_config(config_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {**base, "ok": False, "issues": [str(exc)]}

    source = str(config.get("source") or "").strip().lower()
    issues: list[str] = []
    if source not in SUPPORTED_DIRECTORY_SOURCES:
        issues.append("source must be ldap, ad or json")
    is_ldap = source in {"ldap", "ad"}
    url = str(config.get("url") or config.get("server_uri") or "").strip()
    start_tls = bool(config.get("start_tls"))
    if is_ldap:
        if not (url.startswith("ldap://") or url.startswith("ldaps://")):
            issues.append("LDAP/AD url must start with ldap:// or ldaps://")
        if not (url.startswith("ldaps://") or start_tls):
            issues.append("LDAP/AD sync must use LDAPS or StartTLS")
        if not config.get("user_base_dn"):
            issues.append("user_base_dn is required")
        if not config.get("group_base_dn"):
            issues.append("group_base_dn is required")
        if not _secret_configured(config):
            issues.append("bind secret is not configured through bind_password_env, bind_password_file or anonymous_bind")
    else:
        if not config.get("json_path") and not config.get("input_path"):
            issues.append("json source requires json_path or input_path")
    group_role_map = config.get("group_role_map") or {}
    if not isinstance(group_role_map, dict) or not group_role_map:
        issues.append("group_role_map is required")
    else:
        invalid_roles = sorted({str(role) for role in group_role_map.values() if role not in ROLE_ORDER})
        if invalid_roles:
            issues.append(f"group_role_map contains unknown roles: {', '.join(invalid_roles)}")

    return {
        **base,
        "ok": not issues,
        "source": source,
        "kind": config.get("directory_kind") or ("ad" if source == "ad" else source),
        "tls": {"ldaps": url.startswith("ldaps://"), "start_tls": start_tls},
        "secret_configured": _secret_configured(config) if is_ldap else None,
        "user_base_configured": bool(config.get("user_base_dn")),
        "group_base_configured": bool(config.get("group_base_dn")),
        "group_role_count": len(group_role_map) if isinstance(group_role_map, dict) else 0,
        "deactivate_missing": bool(config.get("deactivate_missing")),
        "delete_missing_groups": bool(config.get("delete_missing_groups")),
        "issues": issues,
    }


def _email_items(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, str):
        return [{"value": value, "primary": True}] if value.strip() else []
    if isinstance(value, list):
        result: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict):
                result.append(item)
            elif item:
                result.append({"value": str(item)})
        return result
    if isinstance(value, dict):
        return [value]
    return []


def _normalize_user(item: dict[str, Any], *, source: str) -> dict[str, Any]:
    user_id = _text(item.get("id") or item.get("user_id") or item.get("externalId") or item.get("external_id") or item.get("userName") or item.get("user_name"))
    user_name = _text(item.get("userName") or item.get("user_name") or item.get("mail") or item.get("email") or user_id)
    if not user_id:
        raise ValueError("directory sync user id is required")
    if not user_name:
        raise ValueError(f"directory sync user_name is required for {user_id}")
    return {
        "user_id": user_id,
        "user_name": user_name,
        "display_name": _text(item.get("displayName") or item.get("display_name") or item.get("displayNamePrintable")),
        "role": _role(item.get("role") or item.get("roles")),
        "department": _text(item.get("department")),
        "project": _text(item.get("project")),
        "clearance": _text(item.get("clearance")),
        "active": _bool_value(item.get("active"), default=True),
        "external_id": _text(item.get("externalId") or item.get("external_id") or item.get("dn") or item.get("distinguishedName")),
        "emails": _email_items(item.get("emails") or item.get("email") or item.get("mail")),
        "metadata": {"source": source, "sync": "directory_sync"},
    }


def _normalize_group(item: dict[str, Any], *, source: str, group_role_map: dict[str, str]) -> dict[str, Any]:
    group_id = _text(item.get("id") or item.get("group_id") or item.get("externalId") or item.get("external_id") or item.get("displayName") or item.get("display_name"))
    display_name = _text(item.get("displayName") or item.get("display_name") or item.get("cn") or group_id)
    if not group_id:
        raise ValueError("directory sync group id is required")
    if not display_name:
        raise ValueError(f"directory sync group display_name is required for {group_id}")
    role = _role(item.get("role") or item.get("roles") or group_role_map.get(group_id) or group_role_map.get(display_name))
    members = item.get("members") or item.get("member_ids") or []
    member_ids = [_text(member.get("value") or member.get("id")) if isinstance(member, dict) else _text(member) for member in members]
    return {
        "group": {
            "group_id": group_id,
            "display_name": display_name,
            "role": role,
            "external_id": _text(item.get("externalId") or item.get("external_id") or item.get("dn") or item.get("distinguishedName")),
            "metadata": {"source": source, "sync": "directory_sync"},
        },
        "members": [member_id for member_id in member_ids if member_id],
    }


def load_json_directory_payload(path: str | Path) -> dict[str, Any]:
    payload = _load_json(path)
    group_role_map = payload.get("group_role_map") if isinstance(payload.get("group_role_map"), dict) else {}
    users = [_normalize_user(item, source="json") for item in payload.get("users", []) if isinstance(item, dict)]
    group_items = [
        _normalize_group(item, source="json", group_role_map=group_role_map)
        for item in payload.get("groups", [])
        if isinstance(item, dict)
    ]
    return {"users": users, "groups": group_items}


def _ldap_password(config: dict[str, Any]) -> str | None:
    if config.get("bind_password_env"):
        return os.getenv(str(config["bind_password_env"]), "")
    if config.get("bind_password_file"):
        return Path(str(config["bind_password_file"])).expanduser().read_text(encoding="utf-8").strip()
    return None


def _ldap_attr(entry: Any, name: str | None) -> Any:
    if not name:
        return None
    attrs = getattr(entry, "entry_attributes_as_dict", {})
    return _first(attrs.get(name))


def load_ldap_directory_payload(config: dict[str, Any]) -> dict[str, Any]:
    try:
        import ldap3  # type: ignore
    except ImportError as exc:
        raise RuntimeError("LDAP sync requires optional dependency ldap3") from exc
    report = directory_sync_config_report(config.get("_path"))
    if not report.get("ok"):
        raise ValueError("; ".join(report.get("issues") or ["invalid LDAP sync config"]))

    url = str(config.get("url") or config.get("server_uri"))
    server = ldap3.Server(url, use_ssl=url.startswith("ldaps://"))
    connection = ldap3.Connection(
        server,
        user=config.get("bind_dn"),
        password=_ldap_password(config),
        auto_bind=True,
    )
    if config.get("start_tls"):
        connection.start_tls()
    attrs = config.get("attributes") or {}
    group_attrs = config.get("group_attributes") or {}
    user_attributes = sorted({value for value in attrs.values() if isinstance(value, str)})
    group_attributes = sorted({value for value in group_attrs.values() if isinstance(value, str)} | {"member"})

    connection.search(config["user_base_dn"], config.get("user_filter") or "(objectClass=person)", attributes=user_attributes)
    users = []
    for entry in connection.entries:
        users.append(
            _normalize_user(
                {
                    "id": _ldap_attr(entry, attrs.get("user_id")) or getattr(entry, "entry_dn", None),
                    "userName": _ldap_attr(entry, attrs.get("user_name")),
                    "displayName": _ldap_attr(entry, attrs.get("display_name")),
                    "department": _ldap_attr(entry, attrs.get("department")),
                    "mail": _ldap_attr(entry, attrs.get("email") or attrs.get("mail")),
                    "externalId": getattr(entry, "entry_dn", None),
                    "active": True,
                },
                source=str(config.get("source") or "ldap"),
            )
        )

    connection.search(config["group_base_dn"], config.get("group_filter") or "(objectClass=group)", attributes=group_attributes)
    group_role_map = config.get("group_role_map") or {}
    groups = []
    dn_to_user = {user.get("external_id"): user["user_id"] for user in users if user.get("external_id")}
    for entry in connection.entries:
        members = []
        for member_dn in _ldap_attr(entry, group_attrs.get("members") or "member") or []:
            members.append(dn_to_user.get(member_dn, member_dn))
        groups.append(
            _normalize_group(
                {
                    "id": _ldap_attr(entry, group_attrs.get("group_id")) or getattr(entry, "entry_dn", None),
                    "displayName": _ldap_attr(entry, group_attrs.get("display_name")),
                    "externalId": getattr(entry, "entry_dn", None),
                    "members": members,
                },
                source=str(config.get("source") or "ldap"),
                group_role_map=group_role_map,
            )
        )
    connection.unbind()
    return {"users": users, "groups": groups}


def load_directory_payload_from_config(config: dict[str, Any], input_path: str | Path | None = None) -> dict[str, Any]:
    source = str(config.get("source") or "").strip().lower()
    if source == "json":
        return load_json_directory_payload(input_path or config.get("json_path") or config.get("input_path"))
    if source in {"ldap", "ad"}:
        return load_ldap_directory_payload(config)
    raise ValueError(f"Unsupported directory sync source: {source}")


def apply_directory_sync(
    conn,
    payload: dict[str, Any],
    *,
    dry_run: bool = True,
    deactivate_missing: bool = False,
    delete_missing_groups: bool = False,
    actor: str = "directory-sync",
    actor_role: str = "admin",
) -> dict[str, Any]:
    users = payload.get("users") or []
    groups = payload.get("groups") or []
    if not isinstance(users, list) or not isinstance(groups, list):
        raise ValueError("directory sync payload must contain users and groups lists")
    incoming_user_ids = {str(user["user_id"]) for user in users if user.get("user_id")}
    incoming_group_ids = {str(item["group"]["group_id"]) for item in groups if item.get("group", {}).get("group_id")}
    existing_user_ids = {str(row["id"]) for row in conn.execute("SELECT id FROM directory_users").fetchall()}
    existing_group_ids = {str(row["id"]) for row in conn.execute("SELECT id FROM directory_groups").fetchall()}
    stats = {
        "dry_run": dry_run,
        "users_seen": len(users),
        "groups_seen": len(groups),
        "users_upserted": 0,
        "groups_upserted": 0,
        "memberships_replaced": 0,
        "users_deactivated": 0,
        "groups_deleted": 0,
        "existing_users": count_directory_users(conn),
        "existing_groups": count_directory_groups(conn),
    }
    if dry_run:
        stats["users_to_deactivate"] = len(existing_user_ids - incoming_user_ids) if deactivate_missing else 0
        stats["groups_to_delete"] = len(existing_group_ids - incoming_group_ids) if delete_missing_groups else 0
        return stats

    for user in users:
        upsert_directory_user(conn, **user, actor=actor, actor_role=actor_role, audit=False)
        stats["users_upserted"] += 1
    for item in groups:
        group = upsert_directory_group(conn, **item["group"], actor=actor, actor_role=actor_role, audit=False)
        replace_directory_group_members(conn, str(group["id"]), item.get("members") or [], actor=actor, actor_role=actor_role, audit=False)
        stats["groups_upserted"] += 1
        stats["memberships_replaced"] += 1
    if deactivate_missing:
        for user_id in sorted(existing_user_ids - incoming_user_ids):
            user = get_directory_user(conn, user_id)
            if user and user.get("active"):
                deactivate_directory_user(conn, user_id, actor=actor, actor_role=actor_role, audit=False)
                stats["users_deactivated"] += 1
    if delete_missing_groups:
        for group_id in sorted(existing_group_ids - incoming_group_ids):
            if get_directory_group(conn, group_id):
                delete_directory_group(conn, group_id, actor=actor, actor_role=actor_role, audit=False)
                stats["groups_deleted"] += 1
    insert_audit(conn, "directory_sync", actor_role, actor=actor, object_type="directory_sync", details=stats)
    return stats
