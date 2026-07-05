from __future__ import annotations

import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.error import URLError
from urllib.request import Request, urlopen


TRACEPARENT_RE = re.compile(r"^[\da-f]{2}-([\da-f]{32})-([\da-f]{16})-([\da-f]{2})$")
TRACE_METRICS: dict[str, int] = {"spans": 0, "exported": 0, "export_errors": 0}


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    sampled: bool = True


def _hex_id(bytes_len: int) -> str:
    while True:
        value = secrets.token_hex(bytes_len)
        if any(char != "0" for char in value):
            return value


def trace_context_from_headers(headers: Mapping[str, str]) -> TraceContext:
    raw_traceparent = headers.get("traceparent") or headers.get("Traceparent")
    if raw_traceparent:
        match = TRACEPARENT_RE.match(raw_traceparent.strip().lower())
        if match:
            trace_id, parent_span_id, flags = match.groups()
            return TraceContext(
                trace_id=trace_id,
                span_id=_hex_id(8),
                parent_span_id=parent_span_id,
                sampled=bool(int(flags, 16) & 1),
            )
    return TraceContext(trace_id=_hex_id(16), span_id=_hex_id(8), sampled=True)


def traceparent_header(context: TraceContext) -> str:
    flags = "01" if context.sampled else "00"
    return f"00-{context.trace_id}-{context.span_id}-{flags}"


def build_http_server_span(
    *,
    context: TraceContext,
    method: str,
    path: str,
    status_code: int,
    start_time_ns: int,
    end_time_ns: int,
    role: str | None = None,
    department: str | None = None,
    project: str | None = None,
) -> dict[str, Any]:
    duration_ms = (end_time_ns - start_time_ns) / 1_000_000
    attributes = {
        "http.request.method": method,
        "url.path": path,
        "http.response.status_code": status_code,
        "duration_ms": round(duration_ms, 2),
        "rdkg.role": role,
        "rdkg.department": department,
        "rdkg.project": project,
    }
    return {
        "trace_id": context.trace_id,
        "span_id": context.span_id,
        "parent_span_id": context.parent_span_id,
        "name": f"{method} {path}",
        "kind": "SERVER",
        "start_time_unix_nano": start_time_ns,
        "end_time_unix_nano": end_time_ns,
        "status_code": "ERROR" if status_code >= 500 else "OK",
        "attributes": {key: value for key, value in attributes.items() if value is not None},
    }


def _otlp_attributes(attributes: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key, value in attributes.items():
        if isinstance(value, bool):
            encoded = {"boolValue": value}
        elif isinstance(value, int):
            encoded = {"intValue": value}
        elif isinstance(value, float):
            encoded = {"doubleValue": value}
        else:
            encoded = {"stringValue": str(value)}
        items.append({"key": key, "value": encoded})
    return items


def otlp_http_trace_payload(span: dict[str, Any], service_name: str = "rd-knowledge-mvp") -> dict[str, Any]:
    parent_span_id = span.get("parent_span_id") or ""
    payload_span = {
        "traceId": span["trace_id"],
        "spanId": span["span_id"],
        "parentSpanId": parent_span_id,
        "name": span["name"],
        "kind": 2,
        "startTimeUnixNano": str(span["start_time_unix_nano"]),
        "endTimeUnixNano": str(span["end_time_unix_nano"]),
        "attributes": _otlp_attributes(span.get("attributes") or {}),
        "status": {"code": 2 if span.get("status_code") == "ERROR" else 1},
    }
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": _otlp_attributes({"service.name": service_name})},
                "scopeSpans": [{"scope": {"name": "rdkg.middleware"}, "spans": [payload_span]}],
            }
        ]
    }


def export_span(span: dict[str, Any]) -> bool:
    TRACE_METRICS["spans"] += 1
    endpoint = os.getenv("RD_KG_OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        return False
    service_name = os.getenv("RD_KG_OTEL_SERVICE_NAME", "rd-knowledge-mvp")
    timeout = float(os.getenv("RD_KG_OTEL_EXPORT_TIMEOUT_SECONDS", "2") or 2)
    payload = otlp_http_trace_payload(span, service_name=service_name)
    request = Request(
        endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout):
            pass
    except (OSError, URLError) as exc:
        TRACE_METRICS["export_errors"] += 1
        if os.getenv("RD_KG_OTEL_FAIL_CLOSED", "").strip().lower() in {"1", "true", "yes", "on"}:
            raise RuntimeError("OpenTelemetry trace export failed") from exc
        return False
    TRACE_METRICS["exported"] += 1
    return True


def now_ns() -> int:
    return time.time_ns()
