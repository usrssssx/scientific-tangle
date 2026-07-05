from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any


DEFAULT_OUTPUT = Path("ops/observability/secrets/rdkg_metrics.jwt")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def generate_hs256_jwt(secret: str, claims: dict[str, Any]) -> str:
    header = {"typ": "JWT", "alg": "HS256"}
    head = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    body = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signed = f"{head}.{body}".encode("ascii")
    signature = _b64url(hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).digest())
    return f"{head}.{body}.{signature}"


def build_metrics_claims(
    *,
    subject: str,
    role: str,
    ttl_seconds: int,
    issuer: str | None = None,
    audience: str | None = None,
) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": now,
        "nbf": now - 5,
        "exp": now + ttl_seconds,
    }
    if issuer:
        claims["iss"] = issuer
    if audience:
        claims["aud"] = audience
    return claims


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an HS256 service JWT for Prometheus metrics scraping.")
    parser.add_argument("--secret-env", default="RD_KG_OIDC_HS256_SECRET")
    parser.add_argument("--subject", default="prometheus")
    parser.add_argument("--role", default="admin")
    parser.add_argument("--ttl-seconds", type=int, default=90 * 24 * 60 * 60)
    parser.add_argument("--issuer", default=os.getenv("RD_KG_OIDC_ISSUER"))
    parser.add_argument("--audience", default=os.getenv("RD_KG_OIDC_AUDIENCE"))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    secret = os.getenv(args.secret_env)
    if not secret:
        raise SystemExit(f"Set ${args.secret_env} before generating a metrics JWT.")
    claims = build_metrics_claims(
        subject=args.subject,
        role=args.role,
        ttl_seconds=args.ttl_seconds,
        issuer=args.issuer,
        audience=args.audience,
    )
    token = generate_hs256_jwt(secret, claims)
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(token + "\n", encoding="utf-8")
    output.chmod(0o600)
    print(json.dumps({"output": str(output), "subject": args.subject, "role": args.role, "expires_at": claims["exp"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
