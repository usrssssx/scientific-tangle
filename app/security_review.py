from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

from .config import DB_PATH, PROJECT_ROOT
from .directory import SCIM_BULK_MAX_OPERATIONS, SCIM_BULK_MAX_PAYLOAD_SIZE
from .directory_sync import directory_sync_config_report
from .policy import ACTION_POLICIES
from .security_review_evidence import security_review_evidence_report
from .storage_encryption import storage_encryption_report

ReviewProfile = Literal["local", "production"]


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int = 0) -> int:
    try:
        return int(os.getenv(name, str(default)) or default)
    except ValueError:
        return default


def _configured(*names: str) -> bool:
    return any(bool(os.getenv(name, "").strip()) for name in names)


def _configured_count(name: str) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return 0
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return len([item for item in parsed if str(item).strip()])
    except json.JSONDecodeError:
        pass
    return len([item for item in value.split(",") if item.strip()])


def _control(
    controls: list[dict[str, Any]],
    control_id: str,
    category: str,
    title: str,
    passed: bool,
    *,
    profile: ReviewProfile,
    production_required: bool = True,
    evidence: dict[str, Any] | None = None,
    remediation: str | None = None,
) -> None:
    if passed:
        status = "pass"
    elif profile == "production" and production_required:
        status = "fail"
    else:
        status = "warn"
    controls.append(
        {
            "id": control_id,
            "category": category,
            "title": title,
            "status": status,
            "evidence": evidence or {},
            "remediation": remediation,
        }
    )


def _observability_bundle_report() -> dict[str, Any]:
    try:
        from scripts.validate_observability_bundle import validate_bundle

        return validate_bundle()
    except Exception as exc:  # noqa: BLE001 - review should report missing validator/runtime details
        return {"ok": False, "errors": [str(exc)]}


def _backup_plan_report() -> dict[str, Any]:
    try:
        from scripts.backup_db import load_backup_plan

        plan = load_backup_plan(PROJECT_ROOT / "ops/backup_plan.example.json")
    except Exception as exc:  # noqa: BLE001 - normalize into review evidence
        return {"ok": False, "error": str(exc)}
    restore_drill = dict(plan.get("restore_drill") or {})
    return {
        "ok": bool(plan.get("encrypted") and restore_drill.get("enabled")),
        "encrypted": bool(plan.get("encrypted")),
        "offsite_configured": bool(plan.get("offsite_dir")),
        "restore_drill_enabled": bool(restore_drill.get("enabled")),
        "retention": plan.get("retention"),
        "offsite_retention": plan.get("offsite_retention"),
    }


def _load_test_report() -> dict[str, Any]:
    try:
        from scripts.load_test_synthetic_graph import PROFILES

        pilot = dict(PROFILES.get("pilot-1m") or {})
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
    return {
        "ok": pilot.get("entities", 0) >= 1_000_000 and pilot.get("depth", 0) >= 4 and float(pilot.get("target_seconds", 99)) <= 5.0,
        "pilot_1m": pilot,
    }


def _dlp_rules_report() -> dict[str, Any]:
    path = Path(os.getenv("RD_KG_DLP_RULES_PATH", PROJECT_ROOT / "data/security/dlp_export_rules.json"))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}
    rules = payload.get("rules")
    names = [item.get("name") for item in rules if isinstance(item, dict)] if isinstance(rules, list) else []
    actions = {item.get("action") for item in rules if isinstance(item, dict)} if isinstance(rules, list) else set()
    return {
        "ok": "secret_assignment" in names and bool(actions & {"approval_required", "block"}),
        "path": str(path),
        "rules": names,
        "actions": sorted(str(action) for action in actions if action),
    }


def security_review_report(profile: ReviewProfile = "local", db_path: Path | str = DB_PATH) -> dict[str, Any]:
    if profile not in {"local", "production"}:
        raise ValueError("security review profile must be local or production")

    controls: list[dict[str, Any]] = []
    oidc_required = _env_bool("RD_KG_OIDC_REQUIRED")
    oidc_jwks = _configured("RD_KG_OIDC_JWKS_URL", "RD_KG_OIDC_DISCOVERY_URL", "RD_KG_OIDC_JWKS_JSON")
    oidc_claims = _configured("RD_KG_OIDC_ISSUER") and _configured("RD_KG_OIDC_AUDIENCE")
    _control(
        controls,
        "auth.oidc_required",
        "identity",
        "OIDC/SSO is required for protected endpoints",
        oidc_required,
        profile=profile,
        evidence={"RD_KG_OIDC_REQUIRED": oidc_required},
        remediation="Set RD_KG_OIDC_REQUIRED=true for production.",
    )
    _control(
        controls,
        "auth.oidc_rs256_or_discovery",
        "identity",
        "OIDC uses JWKS or discovery metadata instead of local-only HS256",
        oidc_required and oidc_jwks and oidc_claims,
        profile=profile,
        evidence={"jwks_or_discovery": oidc_jwks, "issuer_and_audience": oidc_claims},
        remediation="Configure RD_KG_OIDC_ISSUER, RD_KG_OIDC_AUDIENCE and RD_KG_OIDC_JWKS_URL or RD_KG_OIDC_DISCOVERY_URL.",
    )
    directory_required = _env_bool("RD_KG_DIRECTORY_REQUIRED")
    _control(
        controls,
        "auth.directory_lifecycle",
        "identity",
        "Directory lifecycle enforcement is enabled",
        directory_required,
        profile=profile,
        evidence={"RD_KG_DIRECTORY_REQUIRED": directory_required},
        remediation="Set RD_KG_DIRECTORY_REQUIRED=true and provision users through SCIM before pilot access.",
    )
    _control(
        controls,
        "auth.scim_bulk_operations",
        "identity",
        "SCIM bulk lifecycle operations are available for enterprise directory sync",
        SCIM_BULK_MAX_OPERATIONS >= 100 and SCIM_BULK_MAX_PAYLOAD_SIZE >= 1_048_576,
        profile=profile,
        evidence={
            "supported": True,
            "max_operations": SCIM_BULK_MAX_OPERATIONS,
            "max_payload_size": SCIM_BULK_MAX_PAYLOAD_SIZE,
        },
        remediation="Enable /scim/v2/Bulk with enterprise-sized operation and payload limits.",
    )
    directory_sync = directory_sync_config_report()
    _control(
        controls,
        "auth.ad_ldap_sync",
        "identity",
        "Direct AD/LDAP directory sync is configured with TLS and role mapping",
        bool(directory_sync.get("ok")),
        profile=profile,
        evidence=directory_sync,
        remediation="Create ops/directory_sync.json or set RD_KG_DIRECTORY_SYNC_CONFIG with LDAPS/StartTLS, bind secret and group_role_map.",
    )

    required_actions = {
        "metrics.read",
        "audit.read",
        "policy.read",
        "security.review.read",
        "storage.encryption.read",
        "directory.read",
        "directory.write",
        "export.approval.request",
        "export.approval.review",
        "curation.read",
        "curation.write",
    }
    actions = set(ACTION_POLICIES)
    _control(
        controls,
        "authorization.action_matrix",
        "authorization",
        "Central action matrix covers sensitive endpoint families",
        required_actions.issubset(actions),
        profile=profile,
        evidence={"missing": sorted(required_actions - actions), "actions": sorted(actions)},
        remediation="Add missing actions to app.policy.ACTION_POLICIES.",
    )
    pdp_url = _configured("RD_KG_POLICY_ENGINE_URL")
    pdp_auth = _configured(
        "RD_KG_POLICY_ENGINE_BEARER_TOKEN",
        "RD_KG_POLICY_ENGINE_BEARER_TOKEN_FILE",
        "RD_KG_POLICY_ENGINE_HEADERS_JSON",
    )
    pdp_mtls = _configured("RD_KG_POLICY_ENGINE_CA_FILE", "RD_KG_POLICY_ENGINE_CLIENT_CERT")
    _control(
        controls,
        "authorization.external_pdp",
        "authorization",
        "External PDP is configured with service authentication",
        pdp_url and pdp_auth,
        profile=profile,
        evidence={"url_configured": pdp_url, "service_auth_configured": pdp_auth, "mtls_configured": pdp_mtls},
        remediation="Configure RD_KG_POLICY_ENGINE_URL and bearer token/header credentials; add CA/client cert for mTLS where required.",
    )
    _control(
        controls,
        "authorization.policy_bundle_and_ha",
        "authorization",
        "External PDP has managed bundle and HA evidence",
        _configured("RD_KG_POLICY_ENGINE_BUNDLE_REF") and (_configured_count("RD_KG_POLICY_ENGINE_HA_ENDPOINTS") >= 2 or _env_bool("RD_KG_POLICY_ENGINE_HA")),
        profile=profile,
        evidence={
            "bundle_ref_configured": _configured("RD_KG_POLICY_ENGINE_BUNDLE_REF"),
            "ha_endpoints": _configured_count("RD_KG_POLICY_ENGINE_HA_ENDPOINTS"),
            "ha_flag": _env_bool("RD_KG_POLICY_ENGINE_HA"),
        },
        remediation="Set RD_KG_POLICY_ENGINE_BUNDLE_REF and RD_KG_POLICY_ENGINE_HA_ENDPOINTS with at least two PDP endpoints or RD_KG_POLICY_ENGINE_HA=true.",
    )
    policy_audit_enabled = os.getenv("RD_KG_POLICY_DECISION_AUDIT", "true").strip().lower() not in {"0", "false", "no", "off"}
    _control(
        controls,
        "authorization.policy_audit",
        "authorization",
        "Policy decisions are centrally audited",
        policy_audit_enabled,
        profile=profile,
        evidence={"RD_KG_POLICY_DECISION_AUDIT": policy_audit_enabled},
        remediation="Leave RD_KG_POLICY_DECISION_AUDIT enabled for production.",
    )

    dlp = _dlp_rules_report()
    _control(
        controls,
        "dlp.export_rules",
        "dlp",
        "Export DLP rules include sensitive secret detection and approval/block actions",
        bool(dlp.get("ok")),
        profile=profile,
        evidence=dlp,
        remediation="Fix data/security/dlp_export_rules.json or RD_KG_DLP_RULES_PATH.",
    )

    storage = storage_encryption_report(db_path)
    _control(
        controls,
        "encryption.storage_at_rest",
        "encryption",
        "Storage encryption production gate is enabled and ready",
        bool(storage.get("required") and storage.get("ok")),
        profile=profile,
        evidence={
            "required": storage.get("required"),
            "ok": storage.get("ok"),
            "provider": storage.get("provider"),
            "full_storage_configured": storage.get("full_storage_configured"),
            "field_level_enabled": (storage.get("field_level") or {}).get("enabled"),
            "issues": storage.get("issues"),
        },
        remediation="Set RD_KG_REQUIRE_STORAGE_ENCRYPTION=true with valid field-level key and encrypted storage evidence.",
    )

    observability = _observability_bundle_report()
    _control(
        controls,
        "observability.bundle",
        "observability",
        "Prometheus/Grafana/Tempo/Loki/OTEL bundle is self-consistent",
        bool(observability.get("ok")),
        profile=profile,
        evidence=observability,
        remediation="Run scripts/validate_observability_bundle.py and fix reported bundle issues.",
    )
    ops_evidence = {
        "siem_export": _configured("RD_KG_SIEM_EXPORT_URL", "RD_KG_LOG_ARCHIVE_TARGET"),
        "alert_webhook": _configured("RD_KG_ALERT_WEBHOOK_URL", "RD_KG_PAGERDUTY_ROUTING_KEY"),
        "log_retention_days": _env_int("RD_KG_LOG_RETENTION_DAYS"),
        "metrics_retention_days": _env_int("RD_KG_METRICS_RETENTION_DAYS"),
        "trace_retention_days": _env_int("RD_KG_TRACE_RETENTION_DAYS"),
    }
    _control(
        controls,
        "observability.enterprise_retention_and_alerting",
        "observability",
        "Enterprise SIEM/export, alert routing and long-term retention are configured",
        bool(
            ops_evidence["siem_export"]
            and ops_evidence["alert_webhook"]
            and ops_evidence["log_retention_days"] >= 90
            and ops_evidence["metrics_retention_days"] >= 90
            and ops_evidence["trace_retention_days"] >= 30
        ),
        profile=profile,
        evidence=ops_evidence,
        remediation="Configure SIEM/log export, alert routing and retention env vars before production review.",
    )

    backup = _backup_plan_report()
    _control(
        controls,
        "dr.backup_restore_plan",
        "dr",
        "Encrypted backup plan includes restore drill and retention",
        bool(backup.get("ok")),
        profile=profile,
        evidence=backup,
        remediation="Fix ops/backup_plan.example.json so encrypted backups and restore drills are enabled.",
    )
    dr_evidence = {
        "immutable_offsite": _configured("RD_KG_DR_IMMUTABLE_OFFSITE_URI"),
        "independent_environment": _configured("RD_KG_DR_ENVIRONMENT_ID"),
        "job_monitoring": _configured("RD_KG_DR_MONITOR_URL", "RD_KG_DR_ALERT_WEBHOOK_URL"),
    }
    _control(
        controls,
        "dr.independent_environment",
        "dr",
        "Independent DR environment and immutable offsite target are configured",
        bool(dr_evidence["immutable_offsite"] and dr_evidence["independent_environment"] and dr_evidence["job_monitoring"]),
        profile=profile,
        evidence=dr_evidence,
        remediation="Configure RD_KG_DR_IMMUTABLE_OFFSITE_URI, RD_KG_DR_ENVIRONMENT_ID and DR monitoring/alerting.",
    )

    load_test = _load_test_report()
    _control(
        controls,
        "sla.synthetic_1m_profile",
        "sla",
        "Synthetic 1M graph SLA profile exists with depth-4 and <=5s target",
        bool(load_test.get("ok")),
        profile=profile,
        evidence=load_test,
        remediation="Fix scripts/load_test_synthetic_graph.py pilot-1m profile.",
    )

    external_review = security_review_evidence_report()
    _control(
        controls,
        "review.external_signoff",
        "security_review",
        "External security review sign-off and evidence metadata are attached",
        bool(external_review.get("ok")),
        profile=profile,
        evidence=external_review,
        remediation="Create a redacted evidence JSON from ops/security_review_evidence.example.json and set RD_KG_SECURITY_REVIEW_EVIDENCE_FILE.",
    )

    counts = {
        "pass": sum(1 for item in controls if item["status"] == "pass"),
        "warn": sum(1 for item in controls if item["status"] == "warn"),
        "fail": sum(1 for item in controls if item["status"] == "fail"),
    }
    overall_status = "fail" if counts["fail"] else "warn" if counts["warn"] else "pass"
    return {
        "profile": profile,
        "overall_status": overall_status,
        "passed": counts["fail"] == 0,
        "counts": counts,
        "controls": controls,
    }
