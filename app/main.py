from __future__ import annotations

import json
import shutil
import time
from collections import defaultdict
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from .config import API_KEY, DB_PATH, DEFAULT_ROLE, ONTOLOGY_PATH, PUBLIC_PATHS, UPLOAD_DIR
from .db import (
    add_fact_dispute_comment,
    assign_facts,
    connect,
    ensure_demo_db,
    escalate_fact_dispute,
    fact_history,
    insert_audit,
    list_fact_disputes,
    merge_entities,
    open_fact_dispute,
    readiness_report,
    release_fact_assignments,
    resolve_fact_dispute,
    review_fact,
    review_facts_bulk,
    rows_to_dicts,
    split_entity,
    supersede_fact,
)
from .exporters import answer_payload_to_pdf, evidence_pack_to_csv, report_package_to_zip
from .ingest import ingest_document_file, ingest_folder, ingest_zip_archive
from .models import (
    AnswerMode,
    BulkFactReviewRequest,
    EntityMergeRequest,
    EntitySplitRequest,
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
from .search import dashboard_metrics, export_jsonld, export_rdf_turtle, get_graph, run_search
from .security import AccessContext, dlp_sanitize, evaluate_export_policy, safe_audit_details
from .seed_data import rebuild_demo_database
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
    x_role: Annotated[str | None, Header()] = None,
    x_department: Annotated[str | None, Header()] = None,
    x_project: Annotated[str | None, Header()] = None,
    x_clearance: Annotated[str | None, Header()] = None,
) -> AccessContext:
    return AccessContext(role=x_role or DEFAULT_ROLE, department=x_department, project=x_project, clearance=x_clearance)


def audit_export_decision(
    conn,
    action: str,
    context: AccessContext,
    payload,
    export_format: str,
    object_type: str,
    object_id: str | None = None,
    details: dict | None = None,
) -> None:
    decision = evaluate_export_policy(payload, context, export_format)
    audit_details = {
        **(details or {}),
        "format": export_format,
        "dlp": "role-aware",
        "export_policy": decision.audit_details(),
    }
    insert_audit(
        conn,
        action,
        context.role,
        object_type=object_type,
        object_id=object_id,
        details=safe_audit_details(audit_details, context),
    )
    if not decision.allowed:
        raise HTTPException(status_code=403, detail=decision.reason)


@app.middleware("http")
async def security_and_metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    path = request.url.path
    if API_KEY and path not in PUBLIC_PATHS and request.headers.get("x-api-key") != API_KEY:
        elapsed_ms = (time.perf_counter() - start) * 1000
        metric = REQUEST_METRICS[f"{request.method} {path}"]
        metric["count"] += 1
        metric["errors"] += 1
        metric["total_ms"] += elapsed_ms
        metric["max_ms"] = max(metric["max_ms"], elapsed_ms)
        return JSONResponse({"detail": "Invalid or missing X-API-Key"}, status_code=401)
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    metric = REQUEST_METRICS[f"{request.method} {path}"]
    metric["count"] += 1
    metric["errors"] += 1 if response.status_code >= 400 else 0
    metric["total_ms"] += elapsed_ms
    metric["max_ms"] = max(metric["max_ms"], elapsed_ms)
    response.headers["X-Process-Time-Ms"] = f"{elapsed_ms:.2f}"
    print(json.dumps({
        "event": "http_request",
        "method": request.method,
        "path": path,
        "status_code": response.status_code,
        "duration_ms": round(elapsed_ms, 2),
        "role": request.headers.get("x-role") or DEFAULT_ROLE,
        "department": request.headers.get("x-department"),
        "project": request.headers.get("x-project"),
    }, ensure_ascii=False))
    return response


@app.on_event("startup")
def startup() -> None:
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
    if context.role != "admin":
        raise HTTPException(status_code=403, detail="Метрики доступны только admin")
    payload = {}
    for key, item in REQUEST_METRICS.items():
        count = item["count"] or 1
        payload[key] = {
            "count": int(item["count"]),
            "errors": int(item["errors"]),
            "avg_ms": round(item["total_ms"] / count, 2),
            "max_ms": round(item["max_ms"], 2),
        }
    return JSONResponse(payload)


@app.get("/metrics/prometheus")
def prometheus_metrics(context: AccessContext = Depends(access_context)) -> PlainTextResponse:
    if context.role != "admin":
        raise HTTPException(status_code=403, detail="Метрики доступны только admin")
    lines = [
        "# HELP rdkg_http_requests_total HTTP requests by route and status class",
        "# TYPE rdkg_http_requests_total counter",
        "# HELP rdkg_http_request_duration_ms_avg Average request duration in milliseconds",
        "# TYPE rdkg_http_request_duration_ms_avg gauge",
        "# HELP rdkg_http_request_duration_ms_max Max request duration in milliseconds",
        "# TYPE rdkg_http_request_duration_ms_max gauge",
    ]
    for key, item in sorted(REQUEST_METRICS.items()):
        method, route = key.split(" ", 1)
        count = item["count"] or 1
        labels = f'method="{method}",route="{route}"'
        lines.append(f"rdkg_http_requests_total{{{labels},status=\"all\"}} {int(item['count'])}")
        lines.append(f"rdkg_http_requests_total{{{labels},status=\"error\"}} {int(item['errors'])}")
        lines.append(f"rdkg_http_request_duration_ms_avg{{{labels}}} {round(item['total_ms'] / count, 2)}")
        lines.append(f"rdkg_http_request_duration_ms_max{{{labels}}} {round(item['max_ms'], 2)}")
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
    if context.role != "admin":
        raise HTTPException(status_code=403, detail="Нужна роль admin")
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
def jsonld_export(context: AccessContext = Depends(access_context)) -> JSONResponse:
    ensure_ready_or_503()
    with connect() as conn:
        payload = export_jsonld(conn, role=context)
        audit_export_decision(conn, "export_jsonld", context, payload, "jsonld", object_type="graph")
    return JSONResponse(dlp_sanitize(payload, context, export=True))


@app.get("/export/rdf")
def rdf_export(context: AccessContext = Depends(access_context)) -> PlainTextResponse:
    ensure_ready_or_503()
    with connect() as conn:
        payload = export_rdf_turtle(conn, role=context)
        audit_export_decision(conn, "export_rdf", context, payload, "text/turtle", object_type="graph")
    sanitized = dlp_sanitize(payload, context, export=True)
    return PlainTextResponse(str(sanitized), media_type="text/turtle")


@app.post("/ingest/upload")
def upload_document(
    file: Annotated[UploadFile, File()],
    metadata_json: str = "{}",
    context: AccessContext = Depends(access_context),
) -> JSONResponse:
    if context.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Загрузка доступна ролям analyst/admin")
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
    if context.role != "admin":
        raise HTTPException(status_code=403, detail="Ингест локальной папки доступен только admin")
    root = Path(folder_path).expanduser().resolve()
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
    if context.role != "admin":
        raise HTTPException(status_code=403, detail="Аудит доступен только admin")
    ensure_ready_or_503()
    with connect() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        payload = [dict(row) for row in rows]
    return JSONResponse(payload)


@app.get("/curation/facts/pending")
def pending_facts(limit: int = 50, assignee: str | None = None, context: AccessContext = Depends(access_context)) -> JSONResponse:
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Очередь верификации доступна ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Назначение фактов доступно ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Снятие назначений доступно ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Верификация фактов доступна ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Верификация фактов доступна ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="История факта доступна ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Dispute queue доступна ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Dispute workflow доступен ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Dispute comments доступны ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Dispute escalation доступна ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Dispute resolution доступна ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Supersede workflow доступен ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Merge сущностей доступен ролям analyst/admin")
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
    if context.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Split сущности доступен ролям analyst/admin")
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
def export_markdown(query: str, context: AccessContext = Depends(access_context)) -> PlainTextResponse:
    req = SearchRequest(query=query)
    ensure_ready_or_503()
    with connect() as conn:
        payload = attach_answer(run_search(conn, req, role=context))
        audit_export_decision(conn, "export_markdown", context, payload, "markdown", object_type="query", object_id=query)
    sanitized = dlp_sanitize(payload, context, export=True)
    return PlainTextResponse(sanitized["answer_markdown"])


@app.get("/export/table")
def export_table(
    query: str,
    top_k: int = 10,
    answer_mode: AnswerMode = "evidence_table",
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
        )
    sanitized = dlp_sanitize(payload, context, export=True)
    return Response(
        report_package_to_zip(sanitized),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="rdkg-report-package.zip"'},
    )
