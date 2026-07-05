import base64
import asyncio
import hashlib
import hmac
import json
import time
from contextlib import contextmanager

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse

import app.main as main_module
from app.dlp import inspect_export_payload
import app.observability as observability_module
import app.policy as policy_module
import app.security as security_module
from app.db import (
    connect,
    create_export_approval,
    create_schema,
    get_export_approval,
    get_directory_group,
    get_directory_user,
    insert_audit,
    insert_document_chunk,
    insert_edge,
    insert_fact,
    insert_source,
    insert_policy_decision,
    list_directory_group_members,
    list_policy_decisions,
    open_fact_dispute,
    replace_directory_group_members,
    review_fact,
    row_to_dict,
    upsert_directory_group,
    upsert_directory_user,
    upsert_entity,
)
from app.field_encryption import generate_field_encryption_key, is_encrypted_value
from app.models import SearchRequest
from app.observability import TRACE_METRICS, export_span
from app.policy import PolicyError, can_perform_action, policy_matrix, require_action
from app.search import dashboard_metrics, export_jsonld, get_graph, run_search
from app.security import (
    AccessContext,
    AuthError,
    access_context_from_authorization,
    can_access,
    can_access_source,
    can_export_confidentiality,
    dlp_sanitize,
    evaluate_export_policy,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _jwt(claims: dict, secret: str = "oidc-secret") -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    head = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    body = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), f"{head}.{body}".encode("ascii"), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(signature)}"


def _b64url_uint(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    return _b64url(value.to_bytes(size, "big"))


def _rsa_private_key_and_jwk(kid: str = "key-1"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(public_numbers.n),
        "e": _b64url_uint(public_numbers.e),
    }
    return private_key, jwk


def _jwt_rs256(claims: dict, private_key, kid: str = "key-1") -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    head = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    body = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signature = private_key.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{_b64url(signature)}"


def test_dlp_redacts_paths_contacts_and_secrets_for_non_privileged_roles():
    payload = {
        "path": "/restricted/corpus/source.pdf",
        "contact": "expert@example.com",
        "api_key": "should-not-leak",
        "note": "Call +7 495 123-45-67 with token=secret123; keep 0.15-0.30 m/s at 2026-07-04 12:54:06",
    }

    sanitized = dlp_sanitize(payload, AccessContext(role="researcher"), export=True)
    privileged = dlp_sanitize(payload, AccessContext(role="analyst"), export=True)

    assert sanitized["path"] == "[redacted-path]"
    assert sanitized["contact"] == "[redacted-contact]"
    assert "[redacted-phone]" in sanitized["note"]
    assert "[redacted-secret]" in sanitized["note"]
    assert "0.15-0.30 m/s" in sanitized["note"]
    assert "2026-07-04 12:54:06" in sanitized["note"]
    assert privileged["path"] == payload["path"]
    assert privileged["contact"] == payload["contact"]
    assert privileged["api_key"] == "[redacted-secret]"
    assert "[redacted-secret]" in privileged["note"]


def test_field_encryption_protects_sensitive_db_fields_at_rest(monkeypatch, tmp_path):
    monkeypatch.setenv("RD_KG_FIELD_ENCRYPTION_KEY", generate_field_encryption_key())
    with connect(tmp_path / "encrypted-fields.sqlite") as conn:
        create_schema(conn)
        source_id = insert_source(
            conn,
            {"title": "Secret source", "source_type": "internal_report"},
            path="/restricted/corpus/source.pdf",
            abstract="Confidential abstract with process details.",
        )
        insert_audit(
            conn,
            "export_pdf",
            "manager",
            object_type="query",
            object_id="secret query",
            details={"path": "/restricted/corpus/source.pdf", "reason": "board export"},
        )
        raw_source = conn.execute("SELECT path, abstract FROM sources WHERE id = ?", (source_id,)).fetchone()
        raw_audit = conn.execute("SELECT object_id, details_json FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()

        assert is_encrypted_value(raw_source["path"])
        assert is_encrypted_value(raw_source["abstract"])
        assert is_encrypted_value(raw_audit["object_id"])
        assert is_encrypted_value(raw_audit["details_json"])
        assert "/restricted/corpus/source.pdf" not in raw_source["path"]
        assert "board export" not in raw_audit["details_json"]

        source = row_to_dict(raw_source)
        audit = row_to_dict(raw_audit)

    assert source["path"] == "/restricted/corpus/source.pdf"
    assert source["abstract"] == "Confidential abstract with process details."
    assert audit["object_id"] == "secret query"
    assert audit["details"]["reason"] == "board export"


def test_field_encryption_protects_export_approval_justification(monkeypatch, tmp_path):
    monkeypatch.setenv("RD_KG_FIELD_ENCRYPTION_KEY", generate_field_encryption_key())
    with connect(tmp_path / "approval-fields.sqlite") as conn:
        create_schema(conn)
        approval = create_export_approval(
            conn,
            requester="manager-1",
            requester_role="manager",
            action="export_pdf",
            export_format="pdf",
            object_type="query",
            object_id="secret metallurgy protocol",
            payload_hash="abc123",
            max_confidentiality="secret",
            classifications=["secret"],
            reason="Export of secret data requires role admin",
            justification="Board pack needs one controlled extract.",
        )
        raw = conn.execute(
            "SELECT object_id, reason, justification FROM export_approvals WHERE id = ?",
            (approval["id"],),
        ).fetchone()
        loaded = get_export_approval(conn, approval["id"])

    assert is_encrypted_value(raw["reason"])
    assert is_encrypted_value(raw["justification"])
    assert raw["object_id"] == "secret metallurgy protocol"
    assert loaded["reason"] == "Export of secret data requires role admin"
    assert loaded["justification"] == "Board pack needs one controlled extract."


def test_can_access_source_enforces_department_project_and_admin_override():
    source = {
        "confidentiality": "internal",
        "metadata": {
            "department": "hydro",
            "allowed_projects": ["alpha"],
        },
    }

    assert can_access_source(source, AccessContext(role="researcher", department="hydro", project="alpha"))
    assert not can_access_source(source, AccessContext(role="researcher", department="met", project="alpha"))
    assert not can_access_source(source, AccessContext(role="researcher", department="hydro", project="beta"))
    assert can_access_source(source, AccessContext(role="admin", department="met", project="beta"))


def test_bearer_jwt_builds_access_context_from_signed_oidc_claims(monkeypatch):
    now = int(time.time())
    monkeypatch.setenv("RD_KG_OIDC_HS256_SECRET", "oidc-secret")
    monkeypatch.setenv("RD_KG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("RD_KG_OIDC_AUDIENCE", "rdkg")
    token = _jwt(
        {
            "iss": "https://issuer.example",
            "aud": ["rdkg", "other"],
            "sub": "user-123",
            "exp": now + 600,
            "roles": ["researcher", "manager"],
            "department": "hydro",
            "project": "alpha",
            "clearance": "manager",
        }
    )

    context = access_context_from_authorization(
        f"Bearer {token}",
        default_role="researcher",
        header_role="admin",
        header_department="met",
        header_project="beta",
    )

    assert context.auth_method == "jwt"
    assert context.subject == "user-123"
    assert context.role == "manager"
    assert context.department == "hydro"
    assert context.project == "alpha"
    assert context.clearance == "manager"


def test_bearer_jwt_accepts_rs256_token_from_jwks(monkeypatch):
    private_key, jwk = _rsa_private_key_and_jwk()
    now = int(time.time())
    monkeypatch.setenv("RD_KG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("RD_KG_OIDC_AUDIENCE", "rdkg")
    monkeypatch.setenv("RD_KG_OIDC_JWKS_JSON", json.dumps({"keys": [jwk]}))
    token = _jwt_rs256(
        {
            "iss": "https://issuer.example",
            "aud": "rdkg",
            "sub": "analyst-7",
            "exp": now + 600,
            "roles": ["researcher", "analyst"],
            "department": "hydro",
            "project": "alpha",
        },
        private_key,
    )

    context = access_context_from_authorization(f"Bearer {token}", default_role="researcher")

    assert context.auth_method == "jwt"
    assert context.subject == "analyst-7"
    assert context.role == "analyst"
    assert context.department == "hydro"
    assert context.project == "alpha"


def test_rs256_oidc_discovery_fetches_and_caches_jwks(monkeypatch):
    private_key, jwk = _rsa_private_key_and_jwk("discovered-key")
    now = int(time.time())
    security_module._JWKS_CACHE.clear()
    monkeypatch.setenv("RD_KG_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("RD_KG_OIDC_AUDIENCE", "rdkg")
    monkeypatch.setenv("RD_KG_OIDC_JWKS_CACHE_TTL_SECONDS", "600")
    token = _jwt_rs256(
        {
            "iss": "https://issuer.example",
            "aud": ["rdkg"],
            "sub": "manager-2",
            "exp": now + 600,
            "role": "manager",
        },
        private_key,
        kid="discovered-key",
    )
    calls = []

    class FakeResponse:
        def __init__(self, payload: dict):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return json.dumps(self.payload).encode("utf-8")

    def fake_urlopen(request, timeout=0):
        calls.append(request.full_url)
        if request.full_url == "https://issuer.example/.well-known/openid-configuration":
            return FakeResponse({"jwks_uri": "https://issuer.example/jwks"})
        if request.full_url == "https://issuer.example/jwks":
            return FakeResponse({"keys": [jwk]})
        raise AssertionError(request.full_url)

    monkeypatch.setattr(security_module, "urlopen", fake_urlopen)

    first = access_context_from_authorization(f"Bearer {token}", default_role="researcher")
    second = access_context_from_authorization(f"Bearer {token}", default_role="researcher")

    assert first.role == "manager"
    assert second.subject == "manager-2"
    assert calls == [
        "https://issuer.example/.well-known/openid-configuration",
        "https://issuer.example/jwks",
    ]


def test_oidc_group_role_map_handles_ad_dns_and_idp_paths(monkeypatch):
    now = int(time.time())
    monkeypatch.setenv("RD_KG_OIDC_HS256_SECRET", "oidc-secret")
    monkeypatch.setenv(
        "RD_KG_OIDC_GROUP_ROLE_MAP_JSON",
        json.dumps(
            {
                "RDKG-Analysts": "analyst",
                "/corp/rdkg/managers": "manager",
            }
        ),
    )
    token = _jwt(
        {
            "sub": "ad-user-9",
            "exp": now + 600,
            "role": "researcher",
            "groups": [
                "CN=RDKG-Analysts,OU=Groups,DC=example,DC=com",
                "/corp/rdkg/managers",
            ],
        }
    )

    context = access_context_from_authorization(f"Bearer {token}", default_role="researcher")

    assert context.auth_method == "jwt"
    assert context.subject == "ad-user-9"
    assert context.role == "manager"


def test_oidc_group_role_map_file_and_custom_group_claim(monkeypatch, tmp_path):
    group_map = tmp_path / "group-role-map.json"
    group_map.write_text(json.dumps({"RDKG-Admins": "admin"}), encoding="utf-8")
    monkeypatch.setenv("RD_KG_OIDC_HS256_SECRET", "oidc-secret")
    monkeypatch.setenv("RD_KG_OIDC_GROUP_CLAIM", "ad_groups")
    monkeypatch.setenv("RD_KG_OIDC_GROUP_ROLE_MAP_FILE", str(group_map))
    token = _jwt(
        {
            "exp": int(time.time()) + 600,
            "ad_groups": ["CORP\\RDKG-Admins"],
        }
    )

    context = access_context_from_authorization(f"Bearer {token}", default_role="researcher")

    assert context.role == "admin"


def test_oidc_group_role_map_ignores_unknown_application_roles(monkeypatch):
    monkeypatch.setenv("RD_KG_OIDC_HS256_SECRET", "oidc-secret")
    monkeypatch.setenv(
        "RD_KG_OIDC_GROUP_ROLE_MAP_JSON",
        json.dumps({"RDKG-Superusers": "superuser"}),
    )
    token = _jwt(
        {
            "exp": int(time.time()) + 600,
            "groups": ["CN=RDKG-Superusers,OU=Groups,DC=example,DC=com"],
        }
    )

    context = access_context_from_authorization(f"Bearer {token}", default_role="researcher")

    assert context.role == "researcher"


def test_directory_required_enforces_active_subject_and_directory_roles(monkeypatch, tmp_path):
    db_path = tmp_path / "directory-required.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)
        upsert_directory_user(
            conn,
            user_id="user-42",
            user_name="scientist@example.com",
            display_name="Scientist",
            role="researcher",
            department="hydro",
            project="alpha",
            clearance="internal",
            audit=False,
        )
        upsert_directory_group(conn, group_id="g-analysts", display_name="RDKG Analysts", role="analyst", audit=False)
        replace_directory_group_members(conn, "g-analysts", ["user-42"], audit=False)

    @contextmanager
    def fake_connect():
        with connect(db_path) as conn:
            yield conn

    monkeypatch.setattr(main_module, "connect", fake_connect)
    monkeypatch.setenv("RD_KG_DIRECTORY_REQUIRED", "true")
    monkeypatch.setenv("RD_KG_OIDC_HS256_SECRET", "oidc-secret")
    token = _jwt({"sub": "user-42", "exp": int(time.time()) + 600, "role": "admin"})

    context = main_module.access_context(authorization=f"Bearer {token}")

    assert context.auth_method == "jwt+directory"
    assert context.subject == "user-42"
    assert context.role == "analyst"
    assert context.department == "hydro"
    assert context.project == "alpha"
    assert context.clearance == "internal"

    with connect(db_path) as conn:
        user = upsert_directory_user(
            conn,
            user_id="user-42",
            user_name="scientist@example.com",
            role="researcher",
            active=False,
            audit=False,
        )
    assert user["active"] == 0

    with pytest.raises(HTTPException) as exc_info:
        main_module.access_context(authorization=f"Bearer {token}")
    assert exc_info.value.status_code == 403
    assert "disabled" in str(exc_info.value.detail)


def test_directory_required_supports_header_subject_for_local_scim_lifecycle(monkeypatch, tmp_path):
    db_path = tmp_path / "directory-header.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)
        upsert_directory_user(
            conn,
            user_id="local-admin",
            user_name="local-admin",
            role="admin",
            department="security",
            audit=False,
        )

    @contextmanager
    def fake_connect():
        with connect(db_path) as conn:
            yield conn

    monkeypatch.setattr(main_module, "connect", fake_connect)
    monkeypatch.setenv("RD_KG_DIRECTORY_REQUIRED", "true")

    context = main_module.access_context(x_role="researcher", x_subject="local-admin")

    assert context.auth_method == "headers+directory"
    assert context.role == "admin"
    assert context.department == "security"


def test_oidc_required_rejects_missing_or_invalid_token(monkeypatch):
    monkeypatch.setenv("RD_KG_OIDC_REQUIRED", "true")
    monkeypatch.setenv("RD_KG_OIDC_HS256_SECRET", "oidc-secret")
    good_token = _jwt({"exp": int(time.time()) + 600, "role": "analyst"})
    bad_token = good_token.rsplit(".", 1)[0] + ".bad"

    try:
        access_context_from_authorization(None, header_role="admin")
        raise AssertionError("missing token should fail")
    except AuthError as exc:
        assert "required" in str(exc)

    try:
        access_context_from_authorization(f"Bearer {bad_token}")
        raise AssertionError("bad signature should fail")
    except AuthError as exc:
        assert "signature" in str(exc)


def test_scim_user_and_group_lifecycle_endpoints_are_admin_audited(monkeypatch, tmp_path):
    db_path = tmp_path / "scim.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)

    @contextmanager
    def fake_connect():
        with connect(db_path) as conn:
            yield conn

    monkeypatch.setattr(main_module, "connect", fake_connect)
    admin = AccessContext(role="admin", subject="security-admin")
    user_payload = {
        "id": "user-100",
        "externalId": "aad-user-100",
        "userName": "expert@example.com",
        "displayName": "Expert User",
        "active": True,
        "emails": [{"value": "expert@example.com", "primary": True}],
        "roles": [{"value": "researcher", "primary": True}],
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "hydro"},
        "urn:rdkg:params:scim:schemas:extension:security:2.0:User": {"project": "alpha", "clearance": "internal"},
    }

    created_user_response = main_module.scim_create_user(user_payload, context=admin)
    created_user = json.loads(created_user_response.body)

    assert created_user_response.status_code == 201
    assert created_user["id"] == "user-100"
    assert created_user["userName"] == "expert@example.com"
    assert created_user["active"] is True
    assert created_user["roles"][0]["value"] == "researcher"
    assert created_user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["department"] == "hydro"

    group_response = main_module.scim_create_group(
        {
            "id": "group-analysts",
            "displayName": "RDKG Analysts",
            "roles": [{"value": "analyst", "primary": True}],
            "members": [{"value": "user-100"}],
        },
        context=admin,
    )
    group = json.loads(group_response.body)

    assert group_response.status_code == 201
    assert group["members"] == [{"value": "user-100", "display": "expert@example.com", "$ref": "/scim/v2/Users/user-100"}]
    assert group["roles"][0]["value"] == "analyst"

    patched_response = main_module.scim_patch_user(
        "user-100",
        {"Operations": [{"op": "replace", "path": "active", "value": False}]},
        context=admin,
    )
    patched = json.loads(patched_response.body)
    assert patched["active"] is False

    inactive_response = main_module.scim_users(filter="active eq false", context=admin)
    inactive = json.loads(inactive_response.body)
    assert inactive["totalResults"] == 1
    assert inactive["Resources"][0]["id"] == "user-100"

    with connect(db_path) as conn:
        stored_user = get_directory_user(conn, "user-100")
        members = list_directory_group_members(conn, "group-analysts")
        audit_actions = [row["action"] for row in conn.execute("SELECT action FROM audit_log ORDER BY id").fetchall()]

    assert stored_user["active"] == 0
    assert stored_user["emails"][0]["value"] == "expert@example.com"
    assert [member["id"] for member in members] == ["user-100"]
    assert "directory_user_upsert" in audit_actions
    assert "directory_group_members_replace" in audit_actions
    assert "directory_user_list" in audit_actions

    with pytest.raises(HTTPException) as exc_info:
        main_module.scim_create_user(user_payload, context=AccessContext(role="manager"))
    assert exc_info.value.status_code == 403


def test_scim_bulk_users_groups_and_patch_are_atomic_and_audited(monkeypatch, tmp_path):
    db_path = tmp_path / "scim-bulk.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)

    @contextmanager
    def fake_connect():
        with connect(db_path) as conn:
            yield conn

    monkeypatch.setattr(main_module, "connect", fake_connect)
    admin = AccessContext(role="admin", subject="security-admin")

    service_config = json.loads(main_module.scim_service_provider_config(context=admin).body)
    assert service_config["bulk"]["supported"] is True
    assert service_config["bulk"]["maxOperations"] == 100

    response = main_module.scim_bulk(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "bulk-user",
                    "path": "/Users",
                    "data": {
                        "id": "user-bulk-1",
                        "userName": "bulk@example.com",
                        "displayName": "Bulk User",
                        "roles": [{"value": "researcher"}],
                        "active": True,
                    },
                },
                {
                    "method": "POST",
                    "path": "/Groups",
                    "data": {
                        "id": "group-bulk-analysts",
                        "displayName": "Bulk Analysts",
                        "roles": [{"value": "analyst"}],
                        "members": [{"value": "bulkId:bulk-user"}],
                    },
                },
                {
                    "method": "PATCH",
                    "path": "/Users/user-bulk-1",
                    "data": {"Operations": [{"op": "replace", "path": "active", "value": False}]},
                },
            ],
        },
        context=admin,
    )
    payload = json.loads(response.body)

    assert response.status_code == 200
    assert [operation["status"] for operation in payload["Operations"]] == ["201", "201", "200"]
    assert payload["Operations"][1]["response"]["members"][0]["value"] == "user-bulk-1"
    assert payload["Operations"][2]["response"]["active"] is False

    with connect(db_path) as conn:
        stored_user = get_directory_user(conn, "user-bulk-1")
        members = list_directory_group_members(conn, "group-bulk-analysts")
        audit_actions = [row["action"] for row in conn.execute("SELECT action FROM audit_log ORDER BY id").fetchall()]

    assert stored_user["active"] == 0
    assert [member["id"] for member in members] == ["user-bulk-1"]
    assert "directory_bulk" in audit_actions
    assert "directory_user_upsert" in audit_actions
    assert "directory_group_members_replace" in audit_actions


def test_scim_bulk_atomic_failure_rolls_back_and_records_failed_audit(monkeypatch, tmp_path):
    db_path = tmp_path / "scim-bulk-failure.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)

    @contextmanager
    def fake_connect():
        with connect(db_path) as conn:
            yield conn

    monkeypatch.setattr(main_module, "connect", fake_connect)
    admin = AccessContext(role="admin", subject="security-admin")

    response = main_module.scim_bulk(
        {
            "Operations": [
                {
                    "method": "POST",
                    "path": "/Users",
                    "data": {"id": "rolled-back-user", "userName": "rollback@example.com"},
                },
                {
                    "method": "POST",
                    "path": "/Groups",
                    "data": {
                        "id": "broken-group",
                        "displayName": "Broken Group",
                        "members": [{"value": "missing-user"}],
                    },
                },
            ]
        },
        context=admin,
    )
    payload = json.loads(response.body)

    assert response.status_code == 400
    assert [operation["status"] for operation in payload["Operations"]] == ["201", "400"]
    assert "missing-user" in payload["Operations"][1]["response"]["detail"]

    with connect(db_path) as conn:
        assert get_directory_user(conn, "rolled-back-user") is None
        assert get_directory_group(conn, "broken-group") is None
        audit_actions = [row["action"] for row in conn.execute("SELECT action FROM audit_log ORDER BY id").fetchall()]

    assert audit_actions == ["directory_bulk_failed"]

    with pytest.raises(HTTPException) as exc_info:
        main_module.scim_bulk({"Operations": []}, context=AccessContext(role="manager"))
    assert exc_info.value.status_code == 403


def test_export_policy_is_stricter_than_view_access_for_secret_data():
    payload = {
        "evidence_pack": {
            "facts": [
                {
                    "fact_id": 1,
                    "source_title": "Secret protocol",
                    "source_confidentiality": "secret",
                }
            ]
        }
    }

    manager = AccessContext(role="manager")
    admin = AccessContext(role="admin")
    denied = evaluate_export_policy(payload, manager, "pdf")
    allowed = evaluate_export_policy(payload, admin, "pdf")

    assert can_access("secret", manager)
    assert not can_export_confidentiality("secret", manager)
    assert not denied.allowed
    assert denied.max_confidentiality == "secret"
    assert "requires role admin" in denied.reason
    assert allowed.allowed
    assert allowed.audit_details()["max_confidentiality"] == "secret"


def test_dlp_content_inspection_requires_approval_for_secret_assignments(monkeypatch):
    monkeypatch.delenv("RD_KG_DLP_RULES_JSON", raising=False)
    monkeypatch.delenv("RD_KG_DLP_RULES_PATH", raising=False)
    payload = {
        "answer_markdown": "Do not export token=super-secret-value outside the secure room.",
        "evidence_pack": {"facts": [{"source_title": "Operational note", "source_confidentiality": "internal"}]},
    }

    denied = evaluate_export_policy(payload, AccessContext(role="manager"), "pdf")
    allowed = evaluate_export_policy(payload, AccessContext(role="admin"), "pdf")
    audit_details = denied.audit_details()

    assert not denied.allowed
    assert denied.max_confidentiality == "secret"
    assert "DLP content inspection matched: secret_assignment" in denied.reason
    assert allowed.allowed
    assert audit_details["dlp_findings"][0]["rule"] == "secret_assignment"
    assert audit_details["dlp_findings"][0]["paths"] == ["$.answer_markdown"]
    assert "super-secret-value" not in json.dumps(audit_details)


def test_dlp_flag_rule_records_finding_without_blocking_export(monkeypatch):
    monkeypatch.delenv("RD_KG_DLP_RULES_JSON", raising=False)
    monkeypatch.delenv("RD_KG_DLP_RULES_PATH", raising=False)
    payload = {"answer_markdown": "Responsible expert: metallurgist@example.com"}

    decision = evaluate_export_policy(payload, AccessContext(role="researcher"), "markdown")

    assert decision.allowed
    assert decision.max_confidentiality == "public"
    assert decision.audit_details()["dlp_findings"][0]["rule"] == "personal_email"


def test_dlp_rules_can_be_overridden_from_environment(monkeypatch):
    monkeypatch.setenv(
        "RD_KG_DLP_RULES_JSON",
        json.dumps(
            {
                "rules": [
                    {
                        "name": "project_code",
                        "pattern": "PROJECT-[0-9]{3}",
                        "classification": "confidential",
                        "action": "approval_required",
                        "formats": ["csv"],
                    }
                ]
            }
        ),
    )

    findings = inspect_export_payload({"value": "PROJECT-123"}, "csv")

    assert findings[0]["rule"] == "project_code"
    assert findings[0]["classification"] == "confidential"


def test_dlp_block_action_is_not_allowed_even_for_admin(monkeypatch):
    monkeypatch.setenv(
        "RD_KG_DLP_RULES_JSON",
        json.dumps(
            {
                "rules": [
                    {
                        "name": "hard_stop",
                        "pattern": "DO-NOT-EXPORT",
                        "classification": "secret",
                        "action": "block",
                        "formats": ["pdf"],
                    }
                ]
            }
        ),
    )

    decision = evaluate_export_policy({"answer_markdown": "DO-NOT-EXPORT"}, AccessContext(role="admin"), "pdf")

    assert not decision.allowed
    assert decision.reason == "DLP content inspection blocked export"
    assert decision.audit_details()["dlp_findings"][0]["action"] == "block"


def test_central_action_policy_preserves_endpoint_role_semantics():
    assert can_perform_action("metrics.read", AccessContext(role="admin"))
    assert not can_perform_action("metrics.read", AccessContext(role="analyst"))
    assert can_perform_action("curation.write", AccessContext(role="analyst"))
    assert not can_perform_action("curation.write", AccessContext(role="manager"))
    assert "curation.write" in {item["action"] for item in policy_matrix()}

    with pytest.raises(PolicyError):
        require_action("unknown.action", AccessContext(role="admin"))


def test_external_policy_engine_can_deny_locally_allowed_action(monkeypatch):
    calls = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return json.dumps({"result": {"allow": False, "reason": "department export freeze"}}).encode("utf-8")

    def fake_urlopen(request, timeout=0):
        calls.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    context = AccessContext(role="admin", department="met", project="alpha", subject="admin-1", auth_method="jwt")
    resource = {"endpoint": "/metrics", "classification": "internal"}
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_URL", "https://policy.example/v1/data/rdkg/allow")
    monkeypatch.setattr(policy_module, "urlopen", fake_urlopen)

    assert not can_perform_action("metrics.read", context, resource=resource)
    with pytest.raises(PolicyError) as exc_info:
        require_action("metrics.read", context, resource=resource)

    assert "department export freeze" in str(exc_info.value)
    assert calls[0]["input"]["action"] == "metrics.read"
    assert calls[0]["input"]["subject"]["role"] == "admin"
    assert calls[0]["input"]["subject"]["department"] == "met"
    assert calls[0]["input"]["resource"] == resource
    assert calls[0]["input"]["local_policy"]["allowed"] is True


def test_external_policy_engine_supports_service_auth_and_mtls_context(monkeypatch, tmp_path):
    cert_file = tmp_path / "client.crt"
    key_file = tmp_path / "client.key"
    ca_file = tmp_path / "ca.crt"
    cert_file.write_text("cert", encoding="utf-8")
    key_file.write_text("key", encoding="utf-8")
    ca_file.write_text("ca", encoding="utf-8")
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_URL", "https://policy.example/v1/data/rdkg/allow")
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_BEARER_TOKEN", "policy-token")
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_HEADERS_JSON", json.dumps({"X-Policy-Tenant": "rdkg"}))
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_CA_FILE", str(ca_file))
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_CLIENT_CERT", str(cert_file))
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_CLIENT_KEY", str(key_file))
    calls = []

    class FakeSSLContext:
        def __init__(self, cafile=None):
            self.cafile = cafile
            self.cert_chain = None

        def load_cert_chain(self, certfile, keyfile=None):
            self.cert_chain = (certfile, keyfile)

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return json.dumps({"result": {"allow": True, "reason": "external allow"}}).encode("utf-8")

    def fake_create_default_context(cafile=None):
        return FakeSSLContext(cafile=cafile)

    def fake_urlopen(request, timeout=0, context=None):
        calls.append({"request": request, "timeout": timeout, "context": context})
        return FakeResponse()

    monkeypatch.setattr(policy_module.ssl, "create_default_context", fake_create_default_context)
    monkeypatch.setattr(policy_module, "urlopen", fake_urlopen)

    decision = policy_module.evaluate_action_policy(
        "metrics.read",
        AccessContext(role="admin", subject="admin-1"),
        resource={"endpoint": "/metrics"},
    )

    assert decision.allowed
    assert decision.source == "external"
    assert calls[0]["request"].get_header("Authorization") == "Bearer policy-token"
    assert calls[0]["request"].get_header("X-policy-tenant") == "rdkg"
    assert calls[0]["context"].cafile == str(ca_file)
    assert calls[0]["context"].cert_chain == (str(cert_file), str(key_file))


def test_external_policy_engine_failure_modes(monkeypatch):
    def failing_urlopen(request, timeout=0):
        raise OSError("collector unavailable")

    context = AccessContext(role="admin")
    monkeypatch.setenv("RD_KG_POLICY_ENGINE_URL", "https://policy.example/v1/data/rdkg/allow")
    monkeypatch.setattr(policy_module, "urlopen", failing_urlopen)

    assert not can_perform_action("metrics.read", context)

    monkeypatch.setenv("RD_KG_POLICY_ENGINE_FAIL_OPEN", "true")

    assert can_perform_action("metrics.read", context)


def test_policy_decision_audit_records_allow_and_deny(monkeypatch, tmp_path):
    db_path = tmp_path / "policy-decisions.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)

    @contextmanager
    def fake_connect():
        with connect(db_path) as conn:
            yield conn

    monkeypatch.setattr(main_module, "connect", fake_connect)

    main_module.enforce_action("metrics.read", AccessContext(role="admin", subject="admin-1"), resource={"endpoint": "/metrics"})
    with pytest.raises(HTTPException) as exc_info:
        main_module.enforce_action("metrics.read", AccessContext(role="manager", subject="manager-1"), resource={"endpoint": "/metrics"})

    assert exc_info.value.status_code == 403
    with connect(db_path) as conn:
        decisions = list_policy_decisions(conn, action="metrics.read", limit=10)

    assert [item["allowed"] for item in decisions] == [0, 1]
    assert decisions[0]["role"] == "manager"
    assert decisions[0]["subject"] == "manager-1"
    assert decisions[0]["resource"]["endpoint"] == "/metrics"
    assert decisions[1]["role"] == "admin"
    assert decisions[1]["reason"] == "allowed by local action policy"


def test_policy_decision_endpoint_is_admin_only(monkeypatch, tmp_path):
    db_path = tmp_path / "policy-decision-endpoint.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)
        insert_policy_decision(
            conn,
            action="metrics.read",
            allowed=True,
            reason="allowed by local action policy",
            source="local",
            role="admin",
            subject="admin-1",
            resource={"endpoint": "/metrics"},
        )

    @contextmanager
    def fake_connect():
        with connect(db_path) as conn:
            yield conn

    monkeypatch.setattr(main_module, "connect", fake_connect)
    monkeypatch.setattr(main_module, "ensure_ready_or_503", lambda: None)

    response = main_module.security_policy_decisions(context=AccessContext(role="admin", subject="admin-1"))
    payload = json.loads(response.body)

    assert response.status_code == 200
    assert payload["decisions"][0]["action"] == "policy.read"
    assert any(item["action"] == "metrics.read" for item in payload["decisions"])

    with pytest.raises(HTTPException) as exc_info:
        main_module.security_policy_decisions(context=AccessContext(role="manager", subject="manager-1"))
    assert exc_info.value.status_code == 403


def test_http_middleware_propagates_traceparent_and_records_span(monkeypatch):
    TRACE_METRICS.update({"spans": 0, "exported": 0, "export_errors": 0})
    trace_id = "1" * 32
    parent_span_id = "2" * 16
    monkeypatch.setattr(main_module, "API_KEY", None)

    class FakeURL:
        path = "/health"

    class FakeRequest:
        method = "GET"
        url = FakeURL()
        headers = {"traceparent": f"00-{trace_id}-{parent_span_id}-01"}

    async def call_next(request):
        return JSONResponse({"status": "ok"})

    response = asyncio.run(main_module.security_and_metrics_middleware(FakeRequest(), call_next))

    assert response.status_code == 200
    assert response.headers["x-trace-id"] == trace_id
    assert response.headers["traceparent"].startswith(f"00-{trace_id}-")
    assert parent_span_id not in response.headers["traceparent"]
    assert TRACE_METRICS["spans"] >= 1


def test_otlp_exporter_posts_open_telemetry_json(monkeypatch):
    TRACE_METRICS.update({"spans": 0, "exported": 0, "export_errors": 0})
    calls = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    def fake_urlopen(request, timeout=0):
        calls.append({"url": request.full_url, "payload": json.loads(request.data.decode("utf-8"))})
        return FakeResponse()

    monkeypatch.setenv("RD_KG_OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel.example/v1/traces")
    monkeypatch.setenv("RD_KG_OTEL_SERVICE_NAME", "rdkg-test")
    monkeypatch.setattr(observability_module, "urlopen", fake_urlopen)

    exported = export_span(
        {
            "trace_id": "a" * 32,
            "span_id": "b" * 16,
            "parent_span_id": "c" * 16,
            "name": "GET /health",
            "kind": "SERVER",
            "start_time_unix_nano": 100,
            "end_time_unix_nano": 200,
            "status_code": "OK",
            "attributes": {"http.request.method": "GET", "http.response.status_code": 200},
        }
    )

    assert exported is True
    assert TRACE_METRICS["spans"] == 1
    assert TRACE_METRICS["exported"] == 1
    assert calls[0]["url"] == "https://otel.example/v1/traces"
    resource_spans = calls[0]["payload"]["resourceSpans"]
    span = resource_spans[0]["scopeSpans"][0]["spans"][0]
    assert span["traceId"] == "a" * 32
    assert span["spanId"] == "b" * 16
    assert span["parentSpanId"] == "c" * 16
    assert resource_spans[0]["resource"]["attributes"][0]["value"]["stringValue"] == "rdkg-test"


def test_security_policy_endpoint_is_admin_only_and_audited(monkeypatch):
    audit_events = []

    @contextmanager
    def fake_connect():
        yield object()

    def fake_audit(conn, action, role, **kwargs):
        audit_events.append({"action": action, "role": role, **kwargs})

    monkeypatch.setattr(main_module, "ensure_ready_or_503", lambda: None)
    monkeypatch.setattr(main_module, "connect", fake_connect)
    monkeypatch.setattr(main_module, "insert_audit", fake_audit)

    response = main_module.security_policy(context=AccessContext(role="admin"))
    payload = json.loads(response.body)

    assert response.status_code == 200
    assert {item["action"] for item in payload["actions"]} >= {"policy.read", "curation.read", "curation.write"}
    assert audit_events == [{"action": "security_policy", "role": "admin", "object_type": "policy"}]

    with pytest.raises(HTTPException) as exc_info:
        main_module.security_policy(context=AccessContext(role="manager"))
    assert exc_info.value.status_code == 403


def test_search_graph_dashboard_and_jsonld_apply_abac_source_metadata(tmp_path):
    db_path = tmp_path / "security.sqlite"
    with connect(db_path) as conn:
        create_schema(conn)
        hydro_source = insert_source(
            conn,
            {
                "title": "Hydro nickel note",
                "source_type": "test",
                "confidentiality": "internal",
                "department": "hydro",
                "year": 2018,
            },
            path="/restricted/hydro.pdf",
        )
        met_source = insert_source(
            conn,
            {
                "title": "Met nickel note",
                "source_type": "test",
                "confidentiality": "internal",
                "department": "met",
                "year": 2026,
            },
            path="/restricted/met.pdf",
        )
        hydro_doc = insert_document_chunk(conn, hydro_source, 0, "nickel catholyte flow velocity 0.20 m/s", locator="page 1")
        met_doc = insert_document_chunk(conn, met_source, 0, "nickel catholyte flow velocity 0.90 m/s", locator="page 1")
        nickel = upsert_entity(conn, "Material", "nickel", "nickel")
        catholyte = upsert_entity(conn, "Process", "catholyte circulation", "catholyte_circulation")
        hydro_fact_id = insert_fact(
            conn,
            hydro_source,
            nickel,
            "recommended_condition",
            catholyte,
            property_="flow_velocity",
            numeric_value=0.2,
            unit="m_s",
            document_id=hydro_doc,
            evidence="nickel catholyte flow velocity 0.20 m/s",
            evidence_locator="page 1",
        )
        insert_fact(
            conn,
            met_source,
            nickel,
            "recommended_condition",
            catholyte,
            property_="flow_velocity",
            numeric_value=0.9,
            unit="m_s",
            document_id=met_doc,
            evidence="nickel catholyte flow velocity 0.90 m/s",
            evidence_locator="page 1",
        )
        insert_edge(conn, hydro_source, nickel, "uses_process", catholyte, confidence=0.8, evidence="hydro edge")
        insert_edge(conn, met_source, nickel, "uses_process", catholyte, confidence=0.8, evidence="met edge")
        review_fact(conn, hydro_fact_id, reviewer="lead", role="analyst", action="verify")
        open_fact_dispute(
            conn,
            hydro_fact_id,
            opened_by="expert-a",
            role="analyst",
            reason="Conflicting protocol",
            severity="high",
            assignee="lead",
            due_at="2000-01-01 00:00:00",
        )
        insert_audit(conn, "export_table", "researcher", object_type="query", object_id="nickel")

        context = AccessContext(role="researcher", department="hydro")
        result = run_search(conn, SearchRequest(query="nickel catholyte flow velocity", top_k=10), role=context)
        titles = {source["title"] for source in result["sources"]}
        fact_sources = {fact["source_title"] for fact in result["facts"]}
        graph = get_graph(conn, "nickel", role=context)
        dashboard = dashboard_metrics(conn, role=context)
        jsonld = export_jsonld(conn, role=context, limit=10)

    assert titles == {"Hydro nickel note"}
    assert fact_sources == {"Hydro nickel note"}
    assert {edge["source_id"] for edge in graph["edges"]} == {hydro_source}
    assert sum(item["count"] for item in dashboard["sources_by_type"]) == 1
    assert dashboard["manager_summary"]["sources"] == 1
    assert dashboard["manager_summary"]["facts"] == 1
    assert dashboard["manager_summary"]["verified_facts"] == 0
    assert dashboard["manager_summary"]["contradicted_facts"] == 1
    assert dashboard["manager_summary"]["open_disputes"] == 1
    assert dashboard["manager_summary"]["overdue_disputes"] == 1
    assert dashboard["manager_summary"]["stale_sources"] == 1
    assert dashboard["fact_status_counts"] == [{"status": "contradicted", "count": 1}]
    assert dashboard["overdue_disputes"][0]["source_title"] == "Hydro nickel note"
    assert dashboard["team_activity"][0]["reviewer"] in {"expert-a", "lead"}
    assert any(item["action"] == "export_table" for item in dashboard["audit_activity"])
    assert {edge["uses_process"]["source"] for edge in jsonld["@graph"]} == {hydro_source}
