from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.findings.fingerprint import generate_finding_fingerprint
from app.models.finding import Finding
from app.models.scan import Scan


def make_session(tmp_path):
    db_path = tmp_path / "fingerprint.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def test_same_finding_across_scans_has_same_fingerprint():
    first = {
        "scan_id": "scan_001",
        "scanner": "semgrep",
        "category": "sast",
        "rule_id": "python.sql-injection",
        "file_path": "app/main.py",
        "line": 42,
        "component": None,
        "cve": None,
        "cwe": "CWE-89",
    }
    second = {**first, "scan_id": "scan_002"}

    assert generate_finding_fingerprint(first) == generate_finding_fingerprint(second)


def test_different_findings_have_different_fingerprints():
    base = {
        "scanner": "trivy",
        "category": "cve",
        "cve": "CVE-2024-0001",
        "cwe": None,
        "rule_id": None,
        "file_path": "package-lock.json",
        "line": None,
        "component": "lodash",
    }
    changed = {**base, "component": "express"}

    assert generate_finding_fingerprint(base) != generate_finding_fingerprint(changed)


def test_secret_fingerprint_uses_rule_file_and_line_without_secret_value():
    secret_value = "sk_test_secret_value"
    first = {
        "scanner": "gitleaks",
        "category": "secret",
        "rule_id": "generic-api-key",
        "file_path": ".env",
        "line": 7,
        "component": None,
        "cve": None,
        "cwe": None,
        "title": f"Secret detected: {secret_value}",
    }
    second = {**first, "title": "Secret detected: different redacted value"}

    assert generate_finding_fingerprint(first) == generate_finding_fingerprint(second)
    assert secret_value not in generate_finding_fingerprint(first)


def test_finding_model_generates_fingerprint_on_insert(tmp_path):
    db = make_session(tmp_path)
    try:
        db.add(
            Scan(
                id="scan_001",
                project_name="demo",
                target_path="C:/AI/projects/demo",
                status="created",
                created_at=datetime(2026, 5, 1, 10, 0, 0),
            )
        )
        finding = Finding(
            id="finding_001",
            scan_id="scan_001",
            category="sast",
            scanner="semgrep",
            severity="high",
            title="SQL injection",
            rule_id="python.sql-injection",
            file_path="app/main.py",
            line=42,
            component=None,
            cve=None,
            cwe="CWE-89",
            status="open",
        )
        expected = generate_finding_fingerprint(finding)

        db.add(finding)
        db.commit()
        db.refresh(finding)

        assert finding.fingerprint == expected
    finally:
        db.close()
