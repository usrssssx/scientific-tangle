from scripts.validate_observability_bundle import EXPECTED_DASHBOARD_METRICS, OBSERVABILITY_ROOT, validate_bundle
from scripts.generate_metrics_jwt import build_metrics_claims, generate_hs256_jwt
from app.security import access_context_from_authorization


def test_observability_bundle_is_self_consistent():
    report = validate_bundle()

    assert report["ok"], report["errors"]
    assert set(report["dashboard_metrics"]) == EXPECTED_DASHBOARD_METRICS
    assert {"prometheus", "otel-collector", "tempo", "loki", "promtail", "grafana"}.issubset(report["services"])


def test_prometheus_scrape_keeps_metrics_endpoint_authenticated():
    prometheus = (OBSERVABILITY_ROOT / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")

    assert "metrics_path: /metrics/prometheus" in prometheus
    assert "authorization:" in prometheus
    assert "credentials_file: /etc/prometheus/secrets/rdkg_metrics.jwt" in prometheus


def test_generated_metrics_jwt_maps_to_admin_context(monkeypatch):
    monkeypatch.setenv("RD_KG_OIDC_HS256_SECRET", "metrics-secret")
    claims = build_metrics_claims(subject="prometheus", role="admin", ttl_seconds=600)
    token = generate_hs256_jwt("metrics-secret", claims)

    context = access_context_from_authorization(f"Bearer {token}", default_role="researcher")

    assert context.role == "admin"
    assert context.subject == "prometheus"
    assert context.auth_method == "jwt"
