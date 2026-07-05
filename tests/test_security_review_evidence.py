import json

from app.config import PROJECT_ROOT
from app.security_review_evidence import security_review_evidence_report


def test_security_review_evidence_example_is_valid():
    report = security_review_evidence_report(PROJECT_ROOT / "ops/security_review_evidence.example.json")

    assert report["ok"] is True
    assert report["review_id"] == "rdkg-sec-review-2026-pilot-example"
    assert report["categories"]["identity"]["complete"] == 1
    assert report["secret_marker_count"] == 0


def test_security_review_evidence_missing_file_fails(tmp_path):
    report = security_review_evidence_report(tmp_path / "missing.json")

    assert report["ok"] is False
    assert report["configured"] is True
    assert report["issues"]


def test_security_review_evidence_rejects_raw_secret_values(tmp_path):
    path = tmp_path / "evidence.json"
    payload = {
        "review_id": "rdkg-sec-review-secret",
        "status": "approved",
        "approved_at": "2026-07-05",
        "expires_at": "2999-12-31",
        "redacted": True,
        "approved_by": ["Security Reviewer"],
        "scope": {"environment": "production"},
        "control_evidence": {
            "identity": [{"ref": "IDENTITY-1", "sha256": "a" * 64}],
            "authorization": [{"ref": "AUTHZ-1", "sha256": "b" * 64}],
            "dlp": [{"ref": "DLP-1", "sha256": "c" * 64}],
            "encryption": [{"ref": "ENC-1", "sha256": "d" * 64}],
            "observability": [{"ref": "OBS-1", "sha256": "e" * 64}],
            "backup_restore": [{"ref": "BACKUP-1", "sha256": "f" * 64}],
            "disaster_recovery": [{"ref": "DR-1", "sha256": "1" * 64}],
            "load_test": [{"ref": "SLA-1", "sha256": "2" * 64}],
        },
        "notes": "api_key=should-not-be-here",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = security_review_evidence_report(path)

    assert report["ok"] is False
    assert report["secret_marker_count"] == 1
    assert "evidence metadata appears to contain raw secret values" in report["issues"]
