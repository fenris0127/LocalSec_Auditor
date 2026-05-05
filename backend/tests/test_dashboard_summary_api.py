from collections.abc import Generator
from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.crud.finding import create_finding
from app.crud.project import create_project
from app.crud.scan import create_scan
from app.db.base import Base
from app.db.database import get_db_session
from app.main import app


def make_test_client(tmp_path):
    db_path = tmp_path / "dashboard_summary.db"
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db_session() -> Generator[Session, None, None]:
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db_session] = override_get_db_session
    return TestClient(app), session_local


def test_dashboard_summary_returns_recent_scans_severity_counts_and_project_latest(tmp_path):
    client, session_local = make_test_client(tmp_path)
    try:
        db = session_local()
        try:
            create_project(
                db,
                project_id="project_001",
                name="demo",
                root_path="C:/AI/projects/demo",
            )
            create_project(
                db,
                project_id="project_002",
                name="other",
                root_path="C:/AI/projects/other",
            )
            create_scan(
                db,
                scan_id="scan_old",
                project_id="project_001",
                project_name="demo",
                target_path="C:/AI/projects/demo",
                status="completed",
                created_at=datetime(2026, 5, 1, 9, 0, 0),
            )
            create_scan(
                db,
                scan_id="scan_new",
                project_id="project_001",
                project_name="demo",
                target_path="C:/AI/projects/demo",
                status="failed",
                created_at=datetime(2026, 5, 2, 10, 0, 0),
            )
            create_scan(
                db,
                scan_id="scan_other",
                project_id="project_002",
                project_name="other",
                target_path="C:/AI/projects/other",
                status="completed",
                created_at=datetime(2026, 5, 2, 9, 0, 0),
            )
            create_finding(
                db,
                finding_id="finding_high",
                scan_id="scan_new",
                category="sast",
                scanner="semgrep",
                severity="high",
                title="SQL injection",
                status="open",
                rule_id="python.sql-injection",
            )
            create_finding(
                db,
                finding_id="finding_medium",
                scan_id="scan_new",
                category="cve",
                scanner="trivy",
                severity="medium",
                title="Vulnerable dependency",
                status="open",
                component="demo-lib",
                cve="CVE-2026-0001",
            )
            create_finding(
                db,
                finding_id="finding_other_high",
                scan_id="scan_other",
                category="secret",
                scanner="gitleaks",
                severity="high",
                title="Secret detected",
                status="open",
                rule_id="generic-api-key",
            )
        finally:
            db.close()

        response = client.get("/api/dashboard/summary")

        assert response.status_code == 200
        body = response.json()
        assert [scan["id"] for scan in body["recent_scans"]] == [
            "scan_new",
            "scan_other",
            "scan_old",
        ]
        assert body["recent_scans"][0]["finding_count"] == 2
        assert body["severity_counts"] == {"high": 2, "medium": 1}

        latest_by_project = {
            item["project_id"]: item
            for item in body["project_latest_scans"]
        }
        assert latest_by_project["project_001"]["latest_scan_id"] == "scan_new"
        assert latest_by_project["project_001"]["latest_scan_status"] == "failed"
        assert latest_by_project["project_002"]["latest_scan_id"] == "scan_other"
        assert latest_by_project["project_002"]["latest_scan_status"] == "completed"
    finally:
        app.dependency_overrides.clear()


def test_dashboard_summary_returns_empty_payload_without_scans(tmp_path):
    client, _session_local = make_test_client(tmp_path)
    try:
        response = client.get("/api/dashboard/summary")

        assert response.status_code == 200
        assert response.json() == {
            "recent_scans": [],
            "severity_counts": {},
            "project_latest_scans": [],
        }
    finally:
        app.dependency_overrides.clear()
