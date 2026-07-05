import json

from app.config import PROJECT_ROOT
from app.db import connect, create_schema, get_directory_user, list_directory_group_members, upsert_directory_user
from app.directory_sync import (
    apply_directory_sync,
    directory_sync_config_report,
    load_directory_payload_from_config,
    load_directory_sync_config,
)


def _json_sync_payload():
    return {
        "group_role_map": {"group-analysts": "analyst"},
        "users": [
            {
                "id": "user-sync-1",
                "userName": "sync1@example.com",
                "displayName": "Sync One",
                "department": "hydro",
                "project": "alpha",
                "clearance": "internal",
                "roles": [{"value": "researcher"}],
                "emails": [{"value": "sync1@example.com", "primary": True}],
                "active": True,
            },
            {
                "id": "user-sync-2",
                "userName": "sync2@example.com",
                "displayName": "Sync Two",
                "active": True,
            },
        ],
        "groups": [
            {
                "id": "group-analysts",
                "displayName": "RDKG Analysts",
                "members": [{"value": "user-sync-1"}, {"value": "user-sync-2"}],
            }
        ],
    }


def test_directory_sync_config_example_valid_with_secret_env(monkeypatch):
    monkeypatch.setenv("RD_KG_LDAP_BIND_PASSWORD", "not-used-in-test")

    report = directory_sync_config_report(PROJECT_ROOT / "ops/directory_sync.example.json")

    assert report["ok"] is True
    assert report["source"] == "ad"
    assert report["tls"]["ldaps"] is True
    assert report["secret_configured"] is True
    assert report["group_role_count"] >= 5


def test_directory_sync_config_rejects_ldap_without_tls_or_secret(tmp_path):
    path = tmp_path / "bad-directory-sync.json"
    path.write_text(
        json.dumps(
            {
                "source": "ldap",
                "url": "ldap://ad.example.com:389",
                "user_base_dn": "OU=Users,DC=example,DC=com",
                "group_base_dn": "OU=Groups,DC=example,DC=com",
                "group_role_map": {"RDKG Analysts": "analyst"},
            }
        ),
        encoding="utf-8",
    )

    report = directory_sync_config_report(path)

    assert report["ok"] is False
    assert any("LDAPS or StartTLS" in issue for issue in report["issues"])
    assert any("bind secret" in issue for issue in report["issues"])


def test_directory_sync_json_dry_run_and_apply_are_audited(tmp_path):
    db_path = tmp_path / "directory-sync.sqlite"
    source_path = tmp_path / "directory-source.json"
    config_path = tmp_path / "directory-sync.json"
    source_path.write_text(json.dumps(_json_sync_payload()), encoding="utf-8")
    config_path.write_text(
        json.dumps({"source": "json", "json_path": str(source_path), "group_role_map": {"group-analysts": "analyst"}}),
        encoding="utf-8",
    )
    with connect(db_path) as conn:
        create_schema(conn)
        upsert_directory_user(conn, user_id="stale-user", user_name="stale@example.com", audit=False)

    config = load_directory_sync_config(config_path)
    payload = load_directory_payload_from_config(config)
    with connect(db_path) as conn:
        dry_run = apply_directory_sync(conn, payload, dry_run=True, deactivate_missing=True)
        assert dry_run["users_seen"] == 2
        assert dry_run["groups_seen"] == 1
        assert dry_run["users_to_deactivate"] == 1
        assert get_directory_user(conn, "user-sync-1") is None

    with connect(db_path) as conn:
        stats = apply_directory_sync(conn, payload, dry_run=False, deactivate_missing=True, actor="sync-test")
        user = get_directory_user(conn, "user-sync-1")
        stale = get_directory_user(conn, "stale-user")
        members = list_directory_group_members(conn, "group-analysts")
        audit_actions = [row["action"] for row in conn.execute("SELECT action FROM audit_log ORDER BY id").fetchall()]

    assert stats["users_upserted"] == 2
    assert stats["groups_upserted"] == 1
    assert stats["memberships_replaced"] == 1
    assert stats["users_deactivated"] == 1
    assert user["department"] == "hydro"
    assert user["role"] == "researcher"
    assert stale["active"] == 0
    assert [member["id"] for member in members] == ["user-sync-1", "user-sync-2"]
    assert audit_actions == ["directory_sync"]
