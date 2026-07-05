from __future__ import annotations

import json
import os
import shutil
import time
from collections import defaultdict
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from .config import API_KEY, DB_PATH, DEFAULT_ROLE, ONTOLOGY_PATH, PUBLIC_PATHS, UPLOAD_DIR
from .db import (
    add_fact_dispute_comment,
    assign_facts,
    connect,
    count_directory_groups,
    count_directory_users,
    consume_export_approval,
    create_export_approval,
    deactivate_directory_user,
    delete_directory_group,
    ensure_demo_db,
    escalate_fact_dispute,
    fact_history,
    get_directory_group,
    get_directory_user,
    get_export_approval,
    insert_audit,
    insert_policy_decision,
    list_directory_group_members,
    list_directory_groups,
    list_directory_user_groups,
    list_directory_users,
    list_export_approvals,
    list_fact_disputes,
    list_policy_decisions,
    merge_entities,
    open_fact_dispute,
    replace_directory_group_members,
    readiness_report,
    release_fact_assignments,
    review_export_approval,
    resolve_fact_dispute,
    review_fact,
    review_facts_bulk,
    rows_to_dicts,
    split_entity,
    supersede_fact,
    upsert_directory_group,
    upsert_directory_user,
)
from .directory import (
    DirectoryAccessError,
    SCIM_BULK_MAX_OPERATIONS,
    SCIM_BULK_MAX_PAYLOAD_SIZE,
    SCIM_BULK_RESPONSE_SCHEMA,
    apply_directory_context,
    apply_scim_group_patch,
    apply_scim_user_patch,
    directory_required,
    member_ids_from_group_payload,
    parse_scim_group_payload,
    parse_scim_user_payload,
    scim_group_resource,
    scim_list_response,
    scim_user_resource,
)
from .exporters import answer_payload_to_pdf, evidence_pack_to_csv, report_package_to_zip
from .ingest import ingest_document_file, ingest_folder, ingest_zip_archive
from .models import (
    AnswerMode,
    BulkFactReviewRequest,
    EntityMergeRequest,
    EntitySplitRequest,
    ExportApprovalRequest,
    ExportApprovalReviewRequest,
    FactDisputeCommentRequest,
    FactDisputeEscalateRequest,
    FactDisputeRequest,
    FactDisputeResolveRequest,
    FactAssignmentReleaseRequest,
    FactAssignmentRequest,
    FactReviewRequest,
    FactSupersedeRequest,
    GraphRequest,
    IngestMetadata,
    SearchRequest,
)
from .observability import (
    TRACE_METRICS,
    build_http_server_span,
    export_span,
    now_ns,
    trace_context_from_headers,
    traceparent_header,
)
from .policy import PolicyError, evaluate_action_policy, policy_matrix
from .search import dashboard_metrics, export_jsonld, export_rdf_turtle, get_graph, run_search
from .security import (
    AuthError,
    AccessContext,
    access_context_from_authorization,
    dlp_sanitize,
    evaluate_export_policy,
    export_payload_hash,
    safe_audit_details,
)
from .seed_data import rebuild_demo_database
from .security_review import security_review_report
from .storage_encryption import StorageEncryptionError, enforce_storage_encryption_ready, storage_encryption_report
from .synthesize import attach_answer

app = FastAPI(
    title="R&D Mining-Metallurgy Knowledge Map MVP",
    version="0.1.0",
    description="MVP: импорт документов, извлечение сущностей/чисел, граф знаний, поиск и синтез ответа с источниками.",
)

DEMO_QUESTIONS = [
    "Какие методы обессоливания воды подходят для обогатительной фабрики, если исходная вода содержит сульфаты, хлориды, Ca, Mg, Na по 200–300 мг/л, а требуемый сухой остаток — ≤1000 мг/дм³?",
    "Какие технические решения организации циркуляции католита при электроэкстракции никеля описаны в мировой практике, и какая скорость потока считается оптимальной?",
    "Покажите все эксперименты и публикации по распределению Au, Ag и МПГ между медным/никелевым штейном и шлаком за последние 5 лет.",
    "Какие способы закачки шахтных вод в глубокие горизонты применялись в России и за рубежом, и каковы их технико-экономические показатели?",
    "Есть ли пробелы по комбинации холодный климат + кучное выщелачивание + никелевая руда?",
]

REQUEST_METRICS: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0, "errors": 0, "total_ms": 0.0, "max_ms": 0.0})
READINESS_CACHE_TTL_SECONDS = 30.0
READINESS_CACHE: dict[str, object] = {"checked_at": 0.0, "report": None}


def access_context(
    authorization: Annotated[str | None, Header()] = None,
    x_role: Annotated[str | None, Header()] = None,
    x_department: Annotated[str | None, Header()] = None,
    x_project: Annotated[str | None, Header()] = None,
    x_clearance: Annotated[str | None, Header()] = None,
    x_subject: Annotated[str | None, Header()] = None,
) -> AccessContext:
    try:
        context = access_context_from_authorization(
            authorization,
            default_role=DEFAULT_ROLE,
            header_role=x_role,
            header_department=x_department,
            header_project=x_project,
            header_clearance=x_clearance,
            header_subject=x_subject,
        )
        if directory_required():
            with connect() as conn:
                context = apply_directory_context(conn, context)
        return context
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except DirectoryAccessError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


def audit_export_decision(
    conn,
    action: str,
    context: AccessContext,
    payload,
    export_format: str,
    object_type: str,
    object_id: str | None = None,
    details: dict | None = None,
    approval_id: int | None = None,
) -> None:
    decision = evaluate_export_policy(payload, context, export_format)
    approval_details: dict | None = None
    non_overridable_block = any(item.get("action") == "block" for item in (decision.dlp_findings or []))
    if not decision.allowed and approval_id is not None and not non_overridable_block:
        try:
            approval = consume_export_approval(
                conn,
                approval_id,
                requester_role=context.role,
                action=action,
                export_format=export_format,
                object_type=object_type,
                object_id=object_id,
                payload_hash=export_payload_hash(payload),
                max_confidentiality=decision.max_confidentiality,
                actor=context.subject or "demo-user",
            )
            approval_details = {
                "approval_id": approval_id,
                "status": approval.get("status"),
                "allowed_by_approval": True,
                "reviewed_by": approval.get("reviewed_by"),
            }
        except (KeyError, ValueError) as exc:
            approval_details = {
                "approval_id": approval_id,
                "allowed_by_approval": False,
                "reason": str(exc),
            }
    audit_details = {
        **(details or {}),
        "format": export_format,
        "dlp": "role-aware",
        "export_policy": decision.audit_details(),
    }
    if approval_details:
        audit_details["approval"] = approval_details
    insert_audit(
        conn,
        action,
        context.role,
        object_type=object_type,
        object_id=object_id,
        details=safe_audit_details(audit_details, context),
    )
    if not decision.allowed and not (approval_details or {}).get("allowed_by_approval"):
        raise HTTPException(status_code=403, detail=decision.reason)


def _policy_audit_enabled() -> bool:
    return os.getenv("RD_KG_POLICY_DECISION_AUDIT", "true").strip().lower() not in {"0", "false", "no", "off"}


def _record_policy_decision(action: str, context: AccessContext, resource: dict | None, decision) -> None:
    if not _policy_audit_enabled():
        return
    try:
        with connect() as conn:
            insert_policy_decision(
                conn,
                action=action,
                allowed=decision.allowed,
                reason=decision.reason,
                source=decision.source,
                role=context.role,
                subject=context.subject,
                department=context.department,
                project=context.project,
                clearance=context.clearance,
                auth_method=context.auth_method,
                resource=resource,
                external=decision.external,
            )
    except Exception as exc:  # noqa: BLE001 - policy audit must not make authorization fail open/closed differently
        print(json.dumps({"event": "policy_decision_audit_failed", "action": action, "error": str(exc)}, ensure_ascii=False))


def enforce_action(action: str, context: AccessContext, resource: dict | None = None) -> None:
    try:
        decision = evaluate_action_policy(action, context, resource=resource)
    except PolicyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    _record_policy_decision(action, context, resource, decision)
    if not decision.allowed:
        raise HTTPException(status_code=403, detail=decision.reason)


def _default_answer_mode_for_export(export_format: str) -> AnswerMode:
    if export_format == "csv":
        return "evidence_table"
    if export_format in {"pdf", "zip"}:
        return "review"
    return "auto"


def _approval_payload_for_request(conn, request: ExportApprovalRequest, context: AccessContext) -> tuple[dict | str, str, str, str, str, dict]:
    export_format = "text/turtle" if request.export_format == "rdf" else request.export_format
    if request.export_format in {"markdown", "csv", "pdf", "zip"}:
        if not request.query:
            raise HTTPException(status_code=400, detail="query is required for query export approvals")
        answer_mode = request.answer_mode or _default_answer_mode_for_export(request.export_format)
        search_request = SearchRequest(query=request.query, top_k=request.top_k, answer_mode=answer_mode)
        payload = attach_answer(run_search(conn, search_request, role=context))
        action = {
            "markdown": "export_markdown",
            "csv": "export_table",
            "pdf": "export_pdf",
            "zip": "export_report_package",
        }[request.export_format]
        return payload, action, export_format, "query", request.query, {"top_k": request.top_k, "answer_mode": answer_mode}
    if request.query:
        raise HTTPException(status_code=400, detail="query must be omitted for graph export approvals")
    if request.export_format == "jsonld":
        return export_jsonld(conn, role=context), "export_jsonld", "jsonld", "graph", "graph", {}
    return export_rdf_turtle(conn, role=context), "export_rdf", "text/turtle", "graph", "graph", {}


@app.middleware("http")
async def security_and_metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    start_ns = now_ns()
    trace_context = trace_context_from_headers(request.headers)
    path = request.url.path
    if API_KEY and path not in PUBLIC_PATHS and request.headers.get("x-api-key") != API_KEY:
        elapsed_ms = (time.perf_counter() - start) * 1000
        metric = REQUEST_METRICS[f"{request.method} {path}"]
        metric["count"] += 1
        metric["errors"] += 1
        metric["total_ms"] += elapsed_ms
        metric["max_ms"] = max(metric["max_ms"], elapsed_ms)
        response = JSONResponse({"detail": "Invalid or missing X-API-Key"}, status_code=401)
        response.headers["X-Trace-Id"] = trace_context.trace_id
        response.headers["traceparent"] = traceparent_header(trace_context)
        end_ns = now_ns()
        span = build_http_server_span(
            context=trace_context,
            method=request.method,
            path=path,
            status_code=401,
            start_time_ns=start_ns,
            end_time_ns=end_ns,
            role=request.headers.get("x-role") or DEFAULT_ROLE,
            department=request.headers.get("x-department"),
            project=request.headers.get("x-project"),
        )
        export_span(span)
        print(json.dumps({
            "event": "http_request",
            "method": request.method,
            "path": path,
            "status_code": 401,
            "duration_ms": round(elapsed_ms, 2),
            "trace_id": trace_context.trace_id,
            "span_id": trace_context.span_id,
            "parent_span_id": trace_context.parent_span_id,
            "role": request.headers.get("x-role") or DEFAULT_ROLE,
            "department": request.headers.get("x-department"),
            "project": request.headers.get("x-project"),
        }, ensure_ascii=False))
        return response
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    metric = REQUEST_METRICS[f"{request.method} {path}"]
    metric["count"] += 1
    metric["errors"] += 1 if response.status_code >= 400 else 0
    metric["total_ms"] += elapsed_ms
    metric["max_ms"] = max(metric["max_ms"], elapsed_ms)
    response.headers["X-Process-Time-Ms"] = f"{elapsed_ms:.2f}"
    response.headers["X-Trace-Id"] = trace_context.trace_id
    response.headers["traceparent"] = traceparent_header(trace_context)
    end_ns = now_ns()
    span = build_http_server_span(
        context=trace_context,
        method=request.method,
        path=path,
        status_code=response.status_code,
        start_time_ns=start_ns,
        end_time_ns=end_ns,
        role=request.headers.get("x-role") or DEFAULT_ROLE,
        department=request.headers.get("x-department"),
        project=request.headers.get("x-project"),
    )
    export_span(span)
    print(json.dumps({
        "event": "http_request",
        "method": request.method,
        "path": path,
        "status_code": response.status_code,
        "duration_ms": round(elapsed_ms, 2),
        "trace_id": trace_context.trace_id,
        "span_id": trace_context.span_id,
        "parent_span_id": trace_context.parent_span_id,
        "role": request.headers.get("x-role") or DEFAULT_ROLE,
        "department": request.headers.get("x-department"),
        "project": request.headers.get("x-project"),
    }, ensure_ascii=False))
    return response


@app.on_event("startup")
def startup() -> None:
    try:
        enforce_storage_encryption_ready(DB_PATH)
    except StorageEncryptionError as exc:
        raise RuntimeError(str(exc)) from exc
    try:
        ensure_demo_db()
    except RuntimeError as exc:
        print(f"Knowledge base readiness warning: {exc}")


def ensure_ready_or_503() -> None:
    report = cached_readiness_report()
    if not report.get("ready"):
        raise HTTPException(
            status_code=503,
            detail={"message": "Knowledge base is not ready", "readiness": report},
        )


def cached_readiness_report(force: bool = False) -> dict:
    now = time.monotonic()
    cached = READINESS_CACHE.get("report")
    checked_at = float(READINESS_CACHE.get("checked_at") or 0.0)
    if not force and isinstance(cached, dict) and now - checked_at < READINESS_CACHE_TTL_SECONDS:
        return cached
    report = readiness_report()
    if not report.get("ready"):
        try:
            ensure_demo_db()
            report = readiness_report()
        except RuntimeError as exc:
            report.setdefault("issues", []).append(str(exc))
            report["ready"] = False
    READINESS_CACHE["checked_at"] = now
    READINESS_CACHE["report"] = report
    return report


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "db": "[redacted-path]"}


@app.get("/metrics")
def metrics(context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("metrics.read", context, resource={"endpoint": "/metrics"})
    payload = {}
    for key, item in REQUEST_METRICS.items():
        count = item["count"] or 1
        payload[key] = {
            "count": int(item["count"]),
            "errors": int(item["errors"]),
            "avg_ms": round(item["total_ms"] / count, 2),
            "max_ms": round(item["max_ms"], 2),
        }
    payload["_traces"] = dict(TRACE_METRICS)
    return JSONResponse(payload)


@app.get("/metrics/prometheus")
def prometheus_metrics(context: AccessContext = Depends(access_context)) -> PlainTextResponse:
    enforce_action("metrics.read", context, resource={"endpoint": "/metrics/prometheus"})
    lines = [
        "# HELP rdkg_http_requests_total HTTP requests by route and status class",
        "# TYPE rdkg_http_requests_total counter",
        "# HELP rdkg_http_request_duration_ms_avg Average request duration in milliseconds",
        "# TYPE rdkg_http_request_duration_ms_avg gauge",
        "# HELP rdkg_http_request_duration_ms_max Max request duration in milliseconds",
        "# TYPE rdkg_http_request_duration_ms_max gauge",
        "# HELP rdkg_trace_spans_total OpenTelemetry-compatible spans observed by middleware",
        "# TYPE rdkg_trace_spans_total counter",
        "# HELP rdkg_trace_export_total OpenTelemetry-compatible spans exported by middleware",
        "# TYPE rdkg_trace_export_total counter",
    ]
    for key, item in sorted(REQUEST_METRICS.items()):
        method, route = key.split(" ", 1)
        count = item["count"] or 1
        labels = f'method="{method}",route="{route}"'
        lines.append(f"rdkg_http_requests_total{{{labels},status=\"all\"}} {int(item['count'])}")
        lines.append(f"rdkg_http_requests_total{{{labels},status=\"error\"}} {int(item['errors'])}")
        lines.append(f"rdkg_http_request_duration_ms_avg{{{labels}}} {round(item['total_ms'] / count, 2)}")
        lines.append(f"rdkg_http_request_duration_ms_max{{{labels}}} {round(item['max_ms'], 2)}")
    lines.append(f"rdkg_trace_spans_total {int(TRACE_METRICS['spans'])}")
    lines.append(f"rdkg_trace_export_total{{status=\"ok\"}} {int(TRACE_METRICS['exported'])}")
    lines.append(f"rdkg_trace_export_total{{status=\"error\"}} {int(TRACE_METRICS['export_errors'])}")
    return PlainTextResponse("\n".join(lines) + "\n")


@app.get("/ready")
def ready() -> JSONResponse:
    report = cached_readiness_report(force=True)
    return JSONResponse(dlp_sanitize(report, AccessContext(role="external_partner"), export=True), status_code=200 if report["ready"] else 503)


@app.get("/demo/questions")
def demo_questions() -> dict[str, list[str]]:
    return {"questions": DEMO_QUESTIONS}


@app.get("/ontology")
def ontology() -> JSONResponse:
    if not ONTOLOGY_PATH.exists():
        raise HTTPException(status_code=503, detail=f"Ontology file not found: {ONTOLOGY_PATH}")
    return JSONResponse(json.loads(ONTOLOGY_PATH.read_text(encoding="utf-8")))


@app.post("/admin/rebuild-demo")
def rebuild_demo(context: AccessContext = Depends(access_context)) -> dict[str, str]:
    enforce_action("admin.rebuild_demo", context, resource={"db_path": str(DB_PATH)})
    path = rebuild_demo_database(DB_PATH)
    with connect() as conn:
        insert_audit(conn, "rebuild_demo", context.role, object_type="database", object_id=str(path))
    return {"status": "rebuilt", "db": str(path)}


@app.post("/search")
def search(request: SearchRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    ensure_ready_or_503()
    with connect() as conn:
        insert_audit(conn, "search", context.role, object_type="query", object_id=request.query, details=safe_audit_details(request.model_dump(), context))
        payload = run_search(conn, request, role=context)
        answer = attach_answer(payload)
    return JSONResponse(dlp_sanitize(answer, context))


@app.post("/graph")
def graph(request: GraphRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    ensure_ready_or_503()
    with connect() as conn:
        insert_audit(conn, "graph", context.role, object_type="entity", object_id=request.entity, details=safe_audit_details(request.model_dump(), context))
        payload = get_graph(conn, request.entity, role=context, depth=request.depth, limit=request.limit)
    return JSONResponse(dlp_sanitize(payload, context))


@app.get("/dashboard")
def dashboard(context: AccessContext = Depends(access_context)) -> JSONResponse:
    ensure_ready_or_503()
    with connect() as conn:
        insert_audit(conn, "dashboard", context.role, object_type="dashboard")
        payload = dashboard_metrics(conn, role=context)
    return JSONResponse(dlp_sanitize(payload, context))


@app.get("/export/jsonld")
def jsonld_export(approval_id: int | None = None, context: AccessContext = Depends(access_context)) -> JSONResponse:
    ensure_ready_or_503()
    with connect() as conn:
        payload = export_jsonld(conn, role=context)
        audit_export_decision(
            conn,
            "export_jsonld",
            context,
            payload,
            "jsonld",
            object_type="graph",
            object_id="graph",
            approval_id=approval_id,
        )
    return JSONResponse(dlp_sanitize(payload, context, export=True))


@app.get("/export/rdf")
def rdf_export(approval_id: int | None = None, context: AccessContext = Depends(access_context)) -> PlainTextResponse:
    ensure_ready_or_503()
    with connect() as conn:
        payload = export_rdf_turtle(conn, role=context)
        audit_export_decision(
            conn,
            "export_rdf",
            context,
            payload,
            "text/turtle",
            object_type="graph",
            object_id="graph",
            approval_id=approval_id,
        )
    sanitized = dlp_sanitize(payload, context, export=True)
    return PlainTextResponse(str(sanitized), media_type="text/turtle")


@app.post("/ingest/upload")
def upload_document(
    file: Annotated[UploadFile, File()],
    metadata_json: str = "{}",
    context: AccessContext = Depends(access_context),
) -> JSONResponse:
    enforce_action("ingest.upload", context, resource={"filename": file.filename})
    ensure_ready_or_503()
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    target = UPLOAD_DIR / file.filename
    with target.open("wb") as f:
        shutil.copyfileobj(file.file, f)
    try:
        defaults = json.loads(metadata_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="metadata_json должен быть валидным JSON") from exc
    with connect() as conn:
        if target.suffix.lower() == ".zip":
            result = ingest_zip_archive(conn, target, defaults)
            object_type = "zip_archive"
        else:
            result = ingest_document_file(conn, target, defaults)
            object_type = "document"
        insert_audit(conn, "ingest_upload", context.role, object_type=object_type, object_id=str(target), details=safe_audit_details({"result": result}, context))
    return JSONResponse(dlp_sanitize({"status": "ingested", "result": result}, context))


@app.post("/ingest/local-folder")
def ingest_local_folder(
    folder_path: str,
    metadata: IngestMetadata | None = None,
    context: AccessContext = Depends(access_context),
) -> JSONResponse:
    root = Path(folder_path).expanduser().resolve()
    enforce_action("ingest.local_folder", context, resource={"folder_path": str(root)})
    if not root.exists() or not root.is_dir():
        raise HTTPException(status_code=400, detail=f"Папка не найдена: {root}")
    ensure_ready_or_503()
    defaults = metadata.model_dump(exclude_none=True) if metadata else {}
    with connect() as conn:
        result = ingest_folder(conn, root, defaults)
        insert_audit(conn, "ingest_folder", context.role, object_type="folder", object_id=str(root), details={"count": len(result)})
    return JSONResponse(dlp_sanitize({"status": "ingested", "count": len(result), "result": result[:50]}, context))


@app.get("/audit")
def audit(limit: int = 50, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("audit.read", context, resource={"limit": limit})
    ensure_ready_or_503()
    with connect() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        payload = rows_to_dicts(rows)
    return JSONResponse(payload)


@app.get("/security/policy")
def security_policy(context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("policy.read", context, resource={"endpoint": "/security/policy"})
    ensure_ready_or_503()
    with connect() as conn:
        insert_audit(conn, "security_policy", context.role, object_type="policy")
    return JSONResponse(dlp_sanitize({"actions": policy_matrix()}, context))


@app.get("/security/policy/decisions")
def security_policy_decisions(
    action: str | None = None,
    allowed: bool | None = None,
    source: str | None = None,
    limit: int = 100,
    context: AccessContext = Depends(access_context),
) -> JSONResponse:
    enforce_action(
        "policy.read",
        context,
        resource={"endpoint": "/security/policy/decisions", "action": action, "allowed": allowed, "source": source, "limit": limit},
    )
    ensure_ready_or_503()
    with connect() as conn:
        decisions = list_policy_decisions(conn, action=action, allowed=allowed, source=source, limit=limit)
        insert_audit(
            conn,
            "security_policy_decisions",
            context.role,
            object_type="policy_decisions",
            details={"action": action, "allowed": allowed, "source": source, "limit": limit, "count": len(decisions)},
        )
    return JSONResponse(dlp_sanitize({"decisions": decisions}, context))


@app.get("/security/storage-encryption")
def security_storage_encryption(context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("storage.encryption.read", context, resource={"endpoint": "/security/storage-encryption"})
    report = storage_encryption_report(DB_PATH)
    with connect() as conn:
        insert_audit(
            conn,
            "security_storage_encryption",
            context.role,
            object_type="storage_encryption",
            details={"ok": report["ok"], "required": report["required"], "provider": report["provider"], "issues": report["issues"]},
        )
    return JSONResponse(dlp_sanitize(report, context))


@app.get("/security/review")
def security_review(profile: str = "local", context: AccessContext = Depends(access_context)) -> JSONResponse:
    if profile not in {"local", "production"}:
        raise HTTPException(status_code=400, detail="profile must be local or production")
    enforce_action("security.review.read", context, resource={"endpoint": "/security/review", "profile": profile})
    report = security_review_report(profile=profile, db_path=DB_PATH)
    with connect() as conn:
        insert_audit(
            conn,
            "security_review",
            context.role,
            object_type="security_review",
            details={
                "profile": profile,
                "overall_status": report["overall_status"],
                "counts": report["counts"],
            },
        )
    return JSONResponse(dlp_sanitize(report, context))


def _scim_actor(context: AccessContext) -> str:
    return context.subject or "scim-admin"


def _active_filter_from_scim_filter(value: str | None) -> bool | None:
    if not value:
        return None
    normalized = value.strip().lower()
    if normalized == "active eq true":
        return True
    if normalized == "active eq false":
        return False
    raise HTTPException(status_code=400, detail="Only SCIM filter 'active eq true|false' is supported")


def _scim_bulk_bool(value: object, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off"}
    return bool(value)


def _scim_bulk_path_parts(path: object) -> list[str]:
    raw_path = str(path or "").split("?", 1)[0].strip()
    if raw_path.startswith("/scim/v2/"):
        raw_path = raw_path[len("/scim/v2/") :]
    elif raw_path.startswith("scim/v2/"):
        raw_path = raw_path[len("scim/v2/") :]
    return [part for part in raw_path.strip("/").split("/") if part]


def _replace_scim_bulk_ids(value: Any, bulk_ids: dict[str, str]) -> Any:
    if isinstance(value, str) and value.startswith("bulkId:"):
        return bulk_ids.get(value[7:], value)
    if isinstance(value, list):
        return [_replace_scim_bulk_ids(item, bulk_ids) for item in value]
    if isinstance(value, dict):
        return {key: _replace_scim_bulk_ids(item, bulk_ids) for key, item in value.items()}
    return value


def _scim_error_payload(status_code: int, detail: str) -> dict[str, object]:
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": str(status_code),
        "detail": detail,
    }


def _scim_bulk_operation_result(
    operation: dict[str, object],
    *,
    status_code: int,
    location: str | None = None,
    response: dict[str, object] | None = None,
    error: dict[str, object] | None = None,
) -> dict[str, object]:
    item: dict[str, object] = {
        "method": str(operation.get("method") or "").upper(),
        "path": operation.get("path") or "",
        "status": str(status_code),
    }
    if operation.get("bulkId"):
        item["bulkId"] = str(operation["bulkId"])
    if location:
        item["location"] = location
    if response is not None:
        item["response"] = response
    if error is not None:
        item["response"] = error
    return item


def _apply_scim_bulk_operation(conn, operation: dict[str, object], context: AccessContext, bulk_ids: dict[str, str]) -> dict[str, object]:
    method = str(operation.get("method") or "").upper()
    path_parts = _scim_bulk_path_parts(operation.get("path"))
    data = _replace_scim_bulk_ids(operation.get("data") or {}, bulk_ids)
    if not isinstance(data, dict):
        data = {}
    actor = _scim_actor(context)

    if path_parts == ["Users"] and method == "POST":
        user_input = parse_scim_user_payload(data)
        user = upsert_directory_user(conn, **user_input, actor=actor, actor_role=context.role)
        groups = list_directory_user_groups(conn, str(user["id"]))
        resource = scim_user_resource(user, groups)
        if operation.get("bulkId"):
            bulk_ids[str(operation["bulkId"])] = str(user["id"])
        return _scim_bulk_operation_result(
            operation,
            status_code=201,
            location=f"/scim/v2/Users/{user['id']}",
            response=resource,
        )

    if len(path_parts) == 2 and path_parts[0] == "Users":
        user_id = path_parts[1]
        existing = get_directory_user(conn, user_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Directory user not found: {user_id}")
        if method == "PUT":
            user_input = parse_scim_user_payload(data, fallback_id=str(existing["id"]), existing=existing)
            user = upsert_directory_user(conn, **user_input, actor=actor, actor_role=context.role)
            groups = list_directory_user_groups(conn, str(user["id"]))
            return _scim_bulk_operation_result(
                operation,
                status_code=200,
                location=f"/scim/v2/Users/{user['id']}",
                response=scim_user_resource(user, groups),
            )
        if method == "PATCH":
            user_input = apply_scim_user_patch(existing, data)
            user = upsert_directory_user(conn, **user_input, actor=actor, actor_role=context.role)
            groups = list_directory_user_groups(conn, str(user["id"]))
            return _scim_bulk_operation_result(
                operation,
                status_code=200,
                location=f"/scim/v2/Users/{user['id']}",
                response=scim_user_resource(user, groups),
            )
        if method == "DELETE":
            deactivate_directory_user(conn, user_id, actor=actor, actor_role=context.role)
            return _scim_bulk_operation_result(operation, status_code=204, location=f"/scim/v2/Users/{user_id}")

    if path_parts == ["Groups"] and method == "POST":
        group_input = parse_scim_group_payload(data)
        member_ids = member_ids_from_group_payload(data)
        group = upsert_directory_group(conn, **group_input, actor=actor, actor_role=context.role)
        members = replace_directory_group_members(conn, str(group["id"]), member_ids, actor=actor, actor_role=context.role) if member_ids is not None else []
        resource = scim_group_resource(group, members)
        if operation.get("bulkId"):
            bulk_ids[str(operation["bulkId"])] = str(group["id"])
        return _scim_bulk_operation_result(
            operation,
            status_code=201,
            location=f"/scim/v2/Groups/{group['id']}",
            response=resource,
        )

    if len(path_parts) == 2 and path_parts[0] == "Groups":
        group_id = path_parts[1]
        existing = get_directory_group(conn, group_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Directory group not found: {group_id}")
        if method == "PUT":
            group_input = parse_scim_group_payload(data, fallback_id=str(existing["id"]), existing=existing)
            member_ids = member_ids_from_group_payload(data)
            group = upsert_directory_group(conn, **group_input, actor=actor, actor_role=context.role)
            members = replace_directory_group_members(conn, str(group["id"]), member_ids, actor=actor, actor_role=context.role) if member_ids is not None else list_directory_group_members(conn, str(group["id"]))
            return _scim_bulk_operation_result(
                operation,
                status_code=200,
                location=f"/scim/v2/Groups/{group['id']}",
                response=scim_group_resource(group, members),
            )
        if method == "PATCH":
            group_input, member_ids = apply_scim_group_patch(existing, data)
            group = upsert_directory_group(conn, **group_input, actor=actor, actor_role=context.role)
            members = replace_directory_group_members(conn, str(group["id"]), member_ids, actor=actor, actor_role=context.role) if member_ids is not None else list_directory_group_members(conn, str(group["id"]))
            return _scim_bulk_operation_result(
                operation,
                status_code=200,
                location=f"/scim/v2/Groups/{group['id']}",
                response=scim_group_resource(group, members),
            )
        if method == "DELETE":
            delete_directory_group(conn, group_id, actor=actor, actor_role=context.role)
            return _scim_bulk_operation_result(operation, status_code=204, location=f"/scim/v2/Groups/{group_id}")

    raise HTTPException(status_code=400, detail=f"Unsupported SCIM bulk operation: {method} /{'/'.join(path_parts)}")


@app.get("/scim/v2/ServiceProviderConfig")
def scim_service_provider_config(context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.read", context, resource={"endpoint": "/scim/v2/ServiceProviderConfig"})
    return JSONResponse(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {
                "supported": True,
                "maxOperations": SCIM_BULK_MAX_OPERATIONS,
                "maxPayloadSize": SCIM_BULK_MAX_PAYLOAD_SIZE,
            },
            "filter": {"supported": True, "maxResults": 500},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer JWT"}],
        }
    )


@app.post("/scim/v2/Bulk")
def scim_bulk(payload: dict[str, object], context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.write", context, resource={"resource": "bulk", "operation": "bulk"})
    operations = payload.get("Operations") or payload.get("operations") or []
    if not isinstance(operations, list):
        raise HTTPException(status_code=400, detail="SCIM Bulk Operations must be a list")
    if len(operations) > SCIM_BULK_MAX_OPERATIONS:
        raise HTTPException(status_code=413, detail=f"SCIM Bulk supports at most {SCIM_BULK_MAX_OPERATIONS} operations per request")
    try:
        fail_on_errors = max(1, int(payload.get("failOnErrors") or 1))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="SCIM Bulk failOnErrors must be an integer") from exc
    atomic = _scim_bulk_bool(payload.get("atomic"), default=True)
    results: list[dict[str, object]] = []
    errors = 0
    bulk_ids: dict[str, str] = {}
    with connect() as conn:
        if atomic:
            conn.execute("SAVEPOINT scim_bulk")
        for raw_operation in operations:
            if not isinstance(raw_operation, dict):
                raw_operation = {"method": "", "path": "", "data": {}}
            try:
                results.append(_apply_scim_bulk_operation(conn, raw_operation, context, bulk_ids))
            except HTTPException as exc:
                errors += 1
                results.append(
                    _scim_bulk_operation_result(
                        raw_operation,
                        status_code=exc.status_code,
                        error=_scim_error_payload(exc.status_code, str(exc.detail)),
                    )
                )
            except (KeyError, ValueError) as exc:
                errors += 1
                results.append(
                    _scim_bulk_operation_result(
                        raw_operation,
                        status_code=400,
                        error=_scim_error_payload(400, str(exc)),
                    )
                )
            if errors and atomic:
                break
            if errors >= fail_on_errors:
                break
        if atomic and errors:
            conn.execute("ROLLBACK TO scim_bulk")
            conn.execute("RELEASE scim_bulk")
            insert_audit(
                conn,
                "directory_bulk_failed",
                context.role,
                actor=_scim_actor(context),
                object_type="directory_bulk",
                details={"operations": len(operations), "completed": len(results), "errors": errors, "atomic": atomic},
            )
        else:
            if atomic:
                conn.execute("RELEASE scim_bulk")
            insert_audit(
                conn,
                "directory_bulk",
                context.role,
                actor=_scim_actor(context),
                object_type="directory_bulk",
                details={"operations": len(operations), "completed": len(results), "errors": errors, "atomic": atomic},
            )
    body = {
        "schemas": [SCIM_BULK_RESPONSE_SCHEMA],
        "Operations": results,
    }
    return JSONResponse(body, status_code=400 if atomic and errors else 200)


@app.get("/scim/v2/Users")
def scim_users(
    startIndex: int = 1,
    count: int = 100,
    filter: str | None = None,
    context: AccessContext = Depends(access_context),
) -> JSONResponse:
    enforce_action("directory.read", context, resource={"resource": "users", "operation": "list"})
    active = _active_filter_from_scim_filter(filter)
    with connect() as conn:
        users = list_directory_users(conn, active=active, limit=count, start_index=startIndex)
        resources = [scim_user_resource(user, list_directory_user_groups(conn, str(user["id"]))) for user in users]
        total = count_directory_users(conn, active=active)
        insert_audit(
            conn,
            "directory_user_list",
            context.role,
            actor=_scim_actor(context),
            object_type="directory_users",
            details={"count": len(resources), "filter": filter},
        )
    return JSONResponse(scim_list_response(resources, total_results=total, start_index=startIndex))


@app.post("/scim/v2/Users")
def scim_create_user(payload: dict[str, object], context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.write", context, resource={"resource": "user", "operation": "create"})
    try:
        user_input = parse_scim_user_payload(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    with connect() as conn:
        user = upsert_directory_user(conn, **user_input, actor=_scim_actor(context), actor_role=context.role)
        groups = list_directory_user_groups(conn, str(user["id"]))
    return JSONResponse(scim_user_resource(user, groups), status_code=201)


@app.get("/scim/v2/Users/{user_id}")
def scim_user_detail(user_id: str, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.read", context, resource={"resource": "user", "operation": "read", "user_id": user_id})
    with connect() as conn:
        user = get_directory_user(conn, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail=f"Directory user not found: {user_id}")
        groups = list_directory_user_groups(conn, str(user["id"]))
        insert_audit(conn, "directory_user_read", context.role, actor=_scim_actor(context), object_type="directory_user", object_id=str(user["id"]))
    return JSONResponse(scim_user_resource(user, groups))


@app.put("/scim/v2/Users/{user_id}")
def scim_replace_user(user_id: str, payload: dict[str, object], context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.write", context, resource={"resource": "user", "operation": "replace", "user_id": user_id})
    with connect() as conn:
        existing = get_directory_user(conn, user_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Directory user not found: {user_id}")
        try:
            user_input = parse_scim_user_payload(payload, fallback_id=str(existing["id"]), existing=existing)
            user = upsert_directory_user(conn, **user_input, actor=_scim_actor(context), actor_role=context.role)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        groups = list_directory_user_groups(conn, str(user["id"]))
    return JSONResponse(scim_user_resource(user, groups))


@app.patch("/scim/v2/Users/{user_id}")
def scim_patch_user(user_id: str, payload: dict[str, object], context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.write", context, resource={"resource": "user", "operation": "patch", "user_id": user_id})
    with connect() as conn:
        existing = get_directory_user(conn, user_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Directory user not found: {user_id}")
        try:
            user_input = apply_scim_user_patch(existing, payload)
            user = upsert_directory_user(conn, **user_input, actor=_scim_actor(context), actor_role=context.role)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        groups = list_directory_user_groups(conn, str(user["id"]))
    return JSONResponse(scim_user_resource(user, groups))


@app.delete("/scim/v2/Users/{user_id}")
def scim_delete_user(user_id: str, context: AccessContext = Depends(access_context)) -> Response:
    enforce_action("directory.write", context, resource={"resource": "user", "operation": "deactivate", "user_id": user_id})
    with connect() as conn:
        try:
            deactivate_directory_user(conn, user_id, actor=_scim_actor(context), actor_role=context.role)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=204)


@app.get("/scim/v2/Groups")
def scim_groups(startIndex: int = 1, count: int = 100, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.read", context, resource={"resource": "groups", "operation": "list"})
    with connect() as conn:
        groups = list_directory_groups(conn, limit=count, start_index=startIndex)
        resources = [scim_group_resource(group, list_directory_group_members(conn, str(group["id"]))) for group in groups]
        total = count_directory_groups(conn)
        insert_audit(
            conn,
            "directory_group_list",
            context.role,
            actor=_scim_actor(context),
            object_type="directory_groups",
            details={"count": len(resources)},
        )
    return JSONResponse(scim_list_response(resources, total_results=total, start_index=startIndex))


@app.post("/scim/v2/Groups")
def scim_create_group(payload: dict[str, object], context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.write", context, resource={"resource": "group", "operation": "create"})
    try:
        group_input = parse_scim_group_payload(payload)
        member_ids = member_ids_from_group_payload(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    with connect() as conn:
        group = upsert_directory_group(conn, **group_input, actor=_scim_actor(context), actor_role=context.role)
        members = replace_directory_group_members(conn, str(group["id"]), member_ids, actor=_scim_actor(context), actor_role=context.role) if member_ids is not None else []
    return JSONResponse(scim_group_resource(group, members), status_code=201)


@app.get("/scim/v2/Groups/{group_id}")
def scim_group_detail(group_id: str, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.read", context, resource={"resource": "group", "operation": "read", "group_id": group_id})
    with connect() as conn:
        group = get_directory_group(conn, group_id)
        if group is None:
            raise HTTPException(status_code=404, detail=f"Directory group not found: {group_id}")
        members = list_directory_group_members(conn, str(group["id"]))
        insert_audit(conn, "directory_group_read", context.role, actor=_scim_actor(context), object_type="directory_group", object_id=str(group["id"]))
    return JSONResponse(scim_group_resource(group, members))


@app.put("/scim/v2/Groups/{group_id}")
def scim_replace_group(group_id: str, payload: dict[str, object], context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.write", context, resource={"resource": "group", "operation": "replace", "group_id": group_id})
    with connect() as conn:
        existing = get_directory_group(conn, group_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Directory group not found: {group_id}")
        try:
            group_input = parse_scim_group_payload(payload, fallback_id=str(existing["id"]), existing=existing)
            member_ids = member_ids_from_group_payload(payload)
            group = upsert_directory_group(conn, **group_input, actor=_scim_actor(context), actor_role=context.role)
            members = replace_directory_group_members(conn, str(group["id"]), member_ids, actor=_scim_actor(context), actor_role=context.role) if member_ids is not None else list_directory_group_members(conn, str(group["id"]))
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(scim_group_resource(group, members))


@app.patch("/scim/v2/Groups/{group_id}")
def scim_patch_group(group_id: str, payload: dict[str, object], context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("directory.write", context, resource={"resource": "group", "operation": "patch", "group_id": group_id})
    with connect() as conn:
        existing = get_directory_group(conn, group_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Directory group not found: {group_id}")
        try:
            group_input, member_ids = apply_scim_group_patch(existing, payload)
            group = upsert_directory_group(conn, **group_input, actor=_scim_actor(context), actor_role=context.role)
            members = replace_directory_group_members(conn, str(group["id"]), member_ids, actor=_scim_actor(context), actor_role=context.role) if member_ids is not None else list_directory_group_members(conn, str(group["id"]))
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(scim_group_resource(group, members))


@app.delete("/scim/v2/Groups/{group_id}")
def scim_delete_group(group_id: str, context: AccessContext = Depends(access_context)) -> Response:
    enforce_action("directory.write", context, resource={"resource": "group", "operation": "delete", "group_id": group_id})
    with connect() as conn:
        try:
            delete_directory_group(conn, group_id, actor=_scim_actor(context), actor_role=context.role)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=204)


@app.post("/export/approvals")
def request_export_approval(request: ExportApprovalRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("export.approval.request", context, resource=request.model_dump())
    ensure_ready_or_503()
    with connect() as conn:
        payload, action, export_format, object_type, object_id, details = _approval_payload_for_request(conn, request, context)
        decision = evaluate_export_policy(payload, context, export_format)
        if decision.allowed:
            insert_audit(
                conn,
                "export_approval_not_required",
                context.role,
                actor=request.requester,
                object_type=object_type,
                object_id=object_id,
                details=safe_audit_details(
                    {
                        **details,
                        "action": action,
                        "format": export_format,
                        "export_policy": decision.audit_details(),
                    },
                    context,
                ),
            )
            return JSONResponse(dlp_sanitize({"status": "not_required", "decision": decision.audit_details()}, context))
        if any(item.get("action") == "block" for item in (decision.dlp_findings or [])):
            insert_audit(
                conn,
                "export_approval_blocked",
                context.role,
                actor=request.requester,
                object_type=object_type,
                object_id=object_id,
                details=safe_audit_details(
                    {
                        **details,
                        "action": action,
                        "format": export_format,
                        "export_policy": decision.audit_details(),
                    },
                    context,
                ),
            )
            raise HTTPException(status_code=403, detail=decision.reason)
        approval = create_export_approval(
            conn,
            requester=request.requester,
            requester_role=context.role,
            action=action,
            export_format=export_format,
            object_type=object_type,
            object_id=object_id,
            payload_hash=export_payload_hash(payload),
            max_confidentiality=decision.max_confidentiality,
            classifications=decision.classifications,
            reason=decision.reason,
            justification=request.justification,
            expires_at=request.expires_at,
        )
    return JSONResponse(
        dlp_sanitize(
            {"status": approval.get("status"), "approval": approval, "decision": decision.audit_details()},
            context,
        )
    )


@app.get("/export/approvals")
def export_approvals(status: str | None = None, limit: int = 50, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("export.approval.review", context, resource={"status": status, "limit": limit})
    ensure_ready_or_503()
    with connect() as conn:
        approvals = list_export_approvals(conn, status=status, limit=limit)
        insert_audit(
            conn,
            "export_approval_list",
            context.role,
            object_type="export_approvals",
            details={"status": status, "limit": limit, "count": len(approvals)},
        )
    return JSONResponse(dlp_sanitize({"approvals": approvals}, context))


@app.get("/export/approvals/{approval_id}")
def export_approval_detail(approval_id: int, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("export.approval.review", context, resource={"approval_id": approval_id, "operation": "read"})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            approval = get_export_approval(conn, approval_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        insert_audit(conn, "export_approval_read", context.role, object_type="export_approval", object_id=str(approval_id))
    return JSONResponse(dlp_sanitize({"approval": approval}, context))


@app.post("/export/approvals/{approval_id}/approve")
def approve_export_approval(
    approval_id: int,
    request: ExportApprovalReviewRequest,
    context: AccessContext = Depends(access_context),
) -> JSONResponse:
    enforce_action("export.approval.review", context, resource={"approval_id": approval_id, "operation": "approve"})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            approval = review_export_approval(
                conn,
                approval_id,
                approved=True,
                reviewer=request.reviewer,
                reviewer_role=context.role,
                comment=request.comment,
                expires_at=request.expires_at,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": approval.get("status"), "approval": approval}, context))


@app.post("/export/approvals/{approval_id}/reject")
def reject_export_approval(
    approval_id: int,
    request: ExportApprovalReviewRequest,
    context: AccessContext = Depends(access_context),
) -> JSONResponse:
    enforce_action("export.approval.review", context, resource={"approval_id": approval_id, "operation": "reject"})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            approval = review_export_approval(
                conn,
                approval_id,
                approved=False,
                reviewer=request.reviewer,
                reviewer_role=context.role,
                comment=request.comment,
                expires_at=request.expires_at,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": approval.get("status"), "approval": approval}, context))


@app.get("/curation/facts/pending")
def pending_facts(limit: int = 50, assignee: str | None = None, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.read", context, resource={"queue": "pending_facts", "limit": limit, "assignee": assignee})
    ensure_ready_or_503()
    with connect() as conn:
        insert_audit(conn, "curation_pending_facts", context.role, object_type="facts", details={"limit": limit, "assignee": assignee})
        assignment_filter = ""
        values: list[object] = []
        if assignee:
            assignment_filter = "AND fa.assignee = ?"
            values.append(assignee)
        rows = conn.execute(
            f"""
            SELECT f.*, s.title AS source_title, s.year AS source_year,
                   es.name AS subject_name, eo.name AS object_name,
                   fa.id AS assignment_id, fa.assignee, fa.due_at AS assignment_due_at
            FROM facts f
            LEFT JOIN sources s ON s.id = f.source_id
            LEFT JOIN entities es ON es.id = f.subject_id
            LEFT JOIN entities eo ON eo.id = f.object_id
            LEFT JOIN fact_assignments fa ON fa.fact_id = f.id AND fa.status = 'active'
            WHERE (f.status IN ('candidate', 'contradicted') OR f.status IS NULL)
            {assignment_filter}
            ORDER BY f.confidence DESC, f.id DESC
            LIMIT ?
            """,
            values + [limit],
        ).fetchall()
    return JSONResponse(dlp_sanitize(rows_to_dicts(rows), context))


@app.post("/curation/facts/assign")
def assign_facts_endpoint(request: FactAssignmentRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "assign_facts", "fact_ids": request.fact_ids, "assignee": request.assignee})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            assignments = assign_facts(
                conn,
                request.fact_ids,
                assignee=request.assignee,
                assigned_by=request.reviewer,
                role=context.role,
                due_at=request.due_at,
                comment=request.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": "ok", "count": len(assignments), "assignments": assignments}, context))


@app.post("/curation/facts/release-assignment")
def release_fact_assignments_endpoint(request: FactAssignmentReleaseRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "release_fact_assignments", "fact_ids": request.fact_ids})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            assignments = release_fact_assignments(
                conn,
                request.fact_ids,
                reviewer=request.reviewer,
                role=context.role,
                comment=request.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": "ok", "count": len(assignments), "assignments": assignments}, context))


@app.post("/curation/facts/bulk-review")
def bulk_review_facts_endpoint(request: BulkFactReviewRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "bulk_review_facts", "fact_ids": request.fact_ids, "review_action": request.action})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            facts = review_facts_bulk(
                conn,
                request.fact_ids,
                reviewer=request.reviewer,
                role=context.role,
                action=request.action,
                comment=request.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        insert_audit(
            conn,
            "curation_fact_bulk_review",
            context.role,
            actor=request.reviewer,
            object_type="facts",
            object_id=",".join(str(fact_id) for fact_id in dict.fromkeys(request.fact_ids)),
            details=safe_audit_details(request.model_dump(), context),
        )
    return JSONResponse(dlp_sanitize({"status": "ok", "count": len(facts), "facts": facts}, context))


@app.post("/curation/facts/{fact_id}/review")
def review_fact_endpoint(fact_id: int, request: FactReviewRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "review_fact", "fact_id": fact_id, "review_action": request.action})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            fact = review_fact(conn, fact_id, reviewer=request.reviewer, role=context.role, action=request.action, comment=request.comment)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        insert_audit(
            conn,
            "curation_fact_review",
            context.role,
            actor=request.reviewer,
            object_type="fact",
            object_id=str(fact_id),
            details=safe_audit_details(request.model_dump(), context),
        )
    return JSONResponse(dlp_sanitize({"status": "ok", "fact": fact}, context))


@app.get("/curation/facts/{fact_id}/history")
def fact_history_endpoint(fact_id: int, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.read", context, resource={"operation": "fact_history", "fact_id": fact_id})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            payload = fact_history(conn, fact_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize(payload, context))


@app.get("/curation/disputes")
def fact_disputes_endpoint(
    status: str | None = None,
    assignee: str | None = None,
    limit: int = 50,
    context: AccessContext = Depends(access_context),
) -> JSONResponse:
    enforce_action("curation.read", context, resource={"operation": "list_disputes", "status": status, "assignee": assignee, "limit": limit})
    ensure_ready_or_503()
    with connect() as conn:
        insert_audit(
            conn,
            "curation_disputes",
            context.role,
            object_type="disputes",
            details={"status": status, "assignee": assignee, "limit": limit},
        )
        payload = list_fact_disputes(conn, status=status, assignee=assignee, limit=limit)
    return JSONResponse(dlp_sanitize(payload, context))


@app.post("/curation/facts/{fact_id}/dispute")
def open_fact_dispute_endpoint(fact_id: int, request: FactDisputeRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "open_dispute", "fact_id": fact_id, "severity": request.severity})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            dispute = open_fact_dispute(
                conn,
                fact_id=fact_id,
                opened_by=request.reviewer,
                role=context.role,
                reason=request.reason,
                severity=request.severity,
                assignee=request.assignee,
                due_at=request.due_at,
                comment=request.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": "ok", "dispute": dispute}, context))


@app.post("/curation/disputes/{dispute_id}/comment")
def comment_fact_dispute_endpoint(dispute_id: int, request: FactDisputeCommentRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "comment_dispute", "dispute_id": dispute_id})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            comment = add_fact_dispute_comment(
                conn,
                dispute_id=dispute_id,
                author=request.author,
                role=context.role,
                comment=request.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": "ok", "comment": comment}, context))


@app.post("/curation/disputes/{dispute_id}/escalate")
def escalate_fact_dispute_endpoint(dispute_id: int, request: FactDisputeEscalateRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "escalate_dispute", "dispute_id": dispute_id, "assignee": request.assignee})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            dispute = escalate_fact_dispute(
                conn,
                dispute_id=dispute_id,
                reviewer=request.reviewer,
                role=context.role,
                assignee=request.assignee,
                comment=request.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": "ok", "dispute": dispute}, context))


@app.post("/curation/disputes/{dispute_id}/resolve")
def resolve_fact_dispute_endpoint(dispute_id: int, request: FactDisputeResolveRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "resolve_dispute", "dispute_id": dispute_id, "fact_status": request.fact_status})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            dispute = resolve_fact_dispute(
                conn,
                dispute_id=dispute_id,
                reviewer=request.reviewer,
                role=context.role,
                resolution=request.resolution,
                fact_status=request.fact_status,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": "ok", "dispute": dispute}, context))


@app.post("/curation/facts/{fact_id}/supersede")
def supersede_fact_endpoint(fact_id: int, request: FactSupersedeRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "supersede_fact", "fact_id": fact_id, "replacement_fact_id": request.replacement_fact_id})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            payload = supersede_fact(
                conn,
                fact_id=fact_id,
                replacement_fact_id=request.replacement_fact_id,
                reviewer=request.reviewer,
                role=context.role,
                comment=request.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": "ok", "history": payload}, context))


@app.post("/curation/entities/merge")
def merge_entities_endpoint(request: EntityMergeRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "merge_entities", "survivor_id": request.survivor_id, "duplicate_id": request.duplicate_id})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            entity = merge_entities(
                conn,
                survivor_id=request.survivor_id,
                duplicate_id=request.duplicate_id,
                reviewer=request.reviewer,
                role=context.role,
                comment=request.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": "ok", "entity": entity}, context))


@app.post("/curation/entities/split")
def split_entity_endpoint(request: EntitySplitRequest, context: AccessContext = Depends(access_context)) -> JSONResponse:
    enforce_action("curation.write", context, resource={"operation": "split_entity", "source_entity_id": request.source_entity_id, "move_fact_ids": request.move_fact_ids, "move_edge_ids": request.move_edge_ids})
    ensure_ready_or_503()
    with connect() as conn:
        try:
            entity = split_entity(
                conn,
                source_entity_id=request.source_entity_id,
                new_type=request.new_type,
                new_name=request.new_name,
                aliases=request.aliases,
                reviewer=request.reviewer,
                role=context.role,
                comment=request.comment,
                move_fact_ids=request.move_fact_ids,
                move_edge_ids=request.move_edge_ids,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    return JSONResponse(dlp_sanitize({"status": "ok", "entity": entity}, context))


@app.get("/export/markdown")
def export_markdown(
    query: str,
    top_k: int = 10,
    answer_mode: AnswerMode = "auto",
    approval_id: int | None = None,
    context: AccessContext = Depends(access_context),
) -> PlainTextResponse:
    req = SearchRequest(query=query, top_k=top_k, answer_mode=answer_mode)
    ensure_ready_or_503()
    with connect() as conn:
        payload = attach_answer(run_search(conn, req, role=context))
        audit_export_decision(
            conn,
            "export_markdown",
            context,
            payload,
            "markdown",
            object_type="query",
            object_id=query,
            details={"top_k": top_k, "answer_mode": answer_mode},
            approval_id=approval_id,
        )
    sanitized = dlp_sanitize(payload, context, export=True)
    return PlainTextResponse(sanitized["answer_markdown"])


@app.get("/export/table")
def export_table(
    query: str,
    top_k: int = 10,
    answer_mode: AnswerMode = "evidence_table",
    approval_id: int | None = None,
    context: AccessContext = Depends(access_context),
) -> PlainTextResponse:
    req = SearchRequest(query=query, top_k=top_k, answer_mode=answer_mode)
    ensure_ready_or_503()
    with connect() as conn:
        payload = attach_answer(run_search(conn, req, role=context))
        audit_export_decision(
            conn,
            "export_table",
            context,
            payload,
            "csv",
            object_type="query",
            object_id=query,
            details={"top_k": top_k, "answer_mode": answer_mode},
            approval_id=approval_id,
        )
    sanitized = dlp_sanitize(payload, context, export=True)
    return PlainTextResponse(
        evidence_pack_to_csv(sanitized),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="rdkg-evidence.csv"'},
    )


@app.get("/export/pdf")
def export_pdf(
    query: str,
    top_k: int = 10,
    answer_mode: AnswerMode = "review",
    approval_id: int | None = None,
    context: AccessContext = Depends(access_context),
) -> Response:
    req = SearchRequest(query=query, top_k=top_k, answer_mode=answer_mode)
    ensure_ready_or_503()
    with connect() as conn:
        payload = attach_answer(run_search(conn, req, role=context))
        audit_export_decision(
            conn,
            "export_pdf",
            context,
            payload,
            "pdf",
            object_type="query",
            object_id=query,
            details={"top_k": top_k, "answer_mode": answer_mode},
            approval_id=approval_id,
        )
    sanitized = dlp_sanitize(payload, context, export=True)
    return Response(
        answer_payload_to_pdf(sanitized),
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="rdkg-evidence-report.pdf"'},
    )


@app.get("/export/report-package")
def export_report_package(
    query: str,
    top_k: int = 10,
    answer_mode: AnswerMode = "review",
    approval_id: int | None = None,
    context: AccessContext = Depends(access_context),
) -> Response:
    req = SearchRequest(query=query, top_k=top_k, answer_mode=answer_mode)
    ensure_ready_or_503()
    with connect() as conn:
        payload = attach_answer(run_search(conn, req, role=context))
        audit_export_decision(
            conn,
            "export_report_package",
            context,
            payload,
            "zip",
            object_type="query",
            object_id=query,
            details={"top_k": top_k, "answer_mode": answer_mode},
            approval_id=approval_id,
        )
    sanitized = dlp_sanitize(payload, context, export=True)
    return Response(
        report_package_to_zip(sanitized),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="rdkg-report-package.zip"'},
    )
