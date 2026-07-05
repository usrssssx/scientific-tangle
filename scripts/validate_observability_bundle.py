from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OBSERVABILITY_ROOT = PROJECT_ROOT / "ops" / "observability"
REQUIRED_FILES = [
    "docker-compose.yml",
    "prometheus/prometheus.yml",
    "otel-collector-config.yml",
    "tempo/tempo.yml",
    "loki/loki.yml",
    "promtail/promtail.yml",
    "grafana/provisioning/datasources/datasources.yml",
    "grafana/provisioning/dashboards/dashboards.yml",
    "grafana/dashboards/rdkg-overview.json",
    "secrets/README.md",
]
EXPECTED_SERVICES = {"prometheus", "otel-collector", "tempo", "loki", "promtail", "grafana"}
EXPECTED_DASHBOARD_METRICS = {
    "rdkg_http_requests_total",
    "rdkg_http_request_duration_ms_avg",
    "rdkg_http_request_duration_ms_max",
    "rdkg_trace_spans_total",
    "rdkg_trace_export_total",
}


def _read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def _walk_exprs(value: Any) -> list[str]:
    if isinstance(value, dict):
        exprs = []
        for key, child in value.items():
            if key == "expr" and isinstance(child, str):
                exprs.append(child)
            exprs.extend(_walk_exprs(child))
        return exprs
    if isinstance(value, list):
        exprs = []
        for child in value:
            exprs.extend(_walk_exprs(child))
        return exprs
    return []


def validate_bundle(root: Path = OBSERVABILITY_ROOT) -> dict[str, Any]:
    root = root.resolve()
    errors: list[str] = []
    for relative in REQUIRED_FILES:
        path = root / relative
        if not path.exists():
            errors.append(f"missing file: {relative}")
        elif path.is_file() and path.stat().st_size == 0:
            errors.append(f"empty file: {relative}")

    compose = _read(root, "docker-compose.yml") if (root / "docker-compose.yml").exists() else ""
    services_block = compose.split("\nvolumes:", 1)[0]
    services = set(re.findall(r"^  ([a-zA-Z0-9_-]+):$", services_block, flags=re.MULTILINE))
    missing_services = sorted(EXPECTED_SERVICES - services)
    if missing_services:
        errors.append(f"docker compose is missing services: {', '.join(missing_services)}")
    if "host.docker.internal:host-gateway" not in compose:
        errors.append("docker compose must expose host.docker.internal for local API scraping")

    prometheus = _read(root, "prometheus/prometheus.yml") if (root / "prometheus/prometheus.yml").exists() else ""
    if "metrics_path: /metrics/prometheus" not in prometheus:
        errors.append("prometheus must scrape /metrics/prometheus")
    if "credentials_file: /etc/prometheus/secrets/rdkg_metrics.jwt" not in prometheus:
        errors.append("prometheus scrape must use a Bearer JWT credentials_file")
    if "host.docker.internal:8000" not in prometheus:
        errors.append("prometheus target must point at the local API port")

    collector = _read(root, "otel-collector-config.yml") if (root / "otel-collector-config.yml").exists() else ""
    if "endpoint: 0.0.0.0:4318" not in collector:
        errors.append("otel collector must receive OTLP/HTTP traces on 4318")
    if "endpoint: tempo:4317" not in collector:
        errors.append("otel collector must export traces to Tempo")

    promtail = _read(root, "promtail/promtail.yml") if (root / "promtail/promtail.yml").exists() else ""
    if "__path__: /var/log/rdkg/*.jsonl" not in promtail:
        errors.append("promtail must scrape RDKG JSON log files")
    if "trace_id:" not in promtail:
        errors.append("promtail must parse trace_id from structured logs")

    dashboard_metrics: set[str] = set()
    dashboard_path = root / "grafana/dashboards/rdkg-overview.json"
    dashboard_title = None
    if dashboard_path.exists():
        try:
            dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
            dashboard_title = dashboard.get("title")
            if dashboard.get("uid") != "rdkg-overview":
                errors.append("Grafana dashboard uid must be rdkg-overview")
            panels = dashboard.get("panels")
            if not isinstance(panels, list) or len(panels) < 5:
                errors.append("Grafana dashboard must include at least 5 panels")
            for expr in _walk_exprs(dashboard):
                for metric in EXPECTED_DASHBOARD_METRICS:
                    if metric in expr:
                        dashboard_metrics.add(metric)
        except json.JSONDecodeError as exc:
            errors.append(f"Grafana dashboard JSON is invalid: {exc}")
    missing_metrics = sorted(EXPECTED_DASHBOARD_METRICS - dashboard_metrics)
    if missing_metrics:
        errors.append(f"Grafana dashboard does not reference metrics: {', '.join(missing_metrics)}")

    datasources = _read(root, "grafana/provisioning/datasources/datasources.yml") if (root / "grafana/provisioning/datasources/datasources.yml").exists() else ""
    for datasource in ("Prometheus", "Tempo", "Loki"):
        if f"name: {datasource}" not in datasources:
            errors.append(f"Grafana datasource is missing: {datasource}")

    return {
        "ok": not errors,
        "root": str(root),
        "services": sorted(services),
        "dashboard_title": dashboard_title,
        "dashboard_metrics": sorted(dashboard_metrics),
        "errors": errors,
    }


def main() -> None:
    report = validate_bundle()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
