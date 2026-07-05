# Observability secrets

Create `rdkg_metrics.jwt` locally before starting Prometheus. Do not commit it.

The token must validate against the API OIDC/JWT settings and include the `admin`
role so Prometheus can read `/metrics/prometheus`.
