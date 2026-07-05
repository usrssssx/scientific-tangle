from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DICTIONARY_DIR = DATA_DIR / "dictionaries"
SAMPLE_DOCS_DIR = DATA_DIR / "sample_docs"
ONTOLOGY_PATH = DATA_DIR / "ontology" / "rd_ontology.json"
DB_PATH = Path(os.getenv("RD_KG_DB_PATH", DATA_DIR / "rd_knowledge.sqlite"))
UPLOAD_DIR = Path(os.getenv("RD_KG_UPLOAD_DIR", DATA_DIR / "uploads"))
DEFAULT_ROLE = os.getenv("RD_KG_DEFAULT_ROLE", "researcher")
API_KEY = os.getenv("RD_KG_API_KEY")
OIDC_REQUIRED = os.getenv("RD_KG_OIDC_REQUIRED", "").lower() in {"1", "true", "yes", "on"}
OIDC_ISSUER = os.getenv("RD_KG_OIDC_ISSUER")
OIDC_AUDIENCE = os.getenv("RD_KG_OIDC_AUDIENCE")
PUBLIC_PATHS = {
    "/health",
    "/ready",
    "/docs",
    "/openapi.json",
    "/redoc",
}

ROLE_ORDER = {
    "external_partner": 0,
    "researcher": 1,
    "analyst": 2,
    "manager": 3,
    "admin": 4,
}

CONFIDENTIALITY_MIN_ROLE = {
    "public": "external_partner",
    "internal": "researcher",
    "confidential": "analyst",
    "secret": "manager",
}
