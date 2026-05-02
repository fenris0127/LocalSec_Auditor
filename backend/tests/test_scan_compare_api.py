from collections.abc import Generator

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
    db_path = tmp_path / "scan_compare_api.db"
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


def create_comparable_scans(session_local) -> None:
    db = session_local()
    try:
        create_project(
            db,
            project_id="project_001",
            name="demo",
            root_path="C:/AI/projects/demo",
        )
        create_scan(
            db,
            scan_id="scan_base",
            project_id="project_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="completed",
        )
        create_scan(
            db,
            scan_id="scan_target",
            project_id="project_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="completed",
        )
        create_finding(
            db,
            finding_id="base_persistent",
            scan_id="scan_base",
            category="sast",
            scanner="semgrep",
            severity="high",
            title="Persistent SQL injection",
            status="open",
            rule_id="python.sql-injection",
            file_path="src/user.py",
            line=42,
            cwe="CWE-89",
        )
        create_finding(
            db,
            finding_id="base_resolved",
            scan_id="scan_base",
            category="cve",
            scanner="trivy",
            severity="medium",
            title="Resolved vulnerable dependency",
            status="open",
            component="demo-lib",
            installed_version="1.0.0",
            cve="CVE-2026-0001",
        )
        create_finding(
            db,
            finding_id="target_persistent",
            scan_id="scan_target",
            category="sast",
            scanner="semgrep",
            severity="critical",
            title="Persistent SQL injection with updated severity",
            status="open",
            rule_id="python.sql-injection",
            file_path="src/user.py",
            line=42,
            cwe="CWE-89",
        )
        create_finding(
            db,
            finding_id="target_new",
            scan_id="scan_target",
            category="secret",
            scanner="gitleaks",
            severity="high",
            title="New secret finding",
            status="open",
            rule_id="generic-api-key",
            file_path="src/config.py",
            line=7,
        )
    finally:
        db.close()


def test_scan_compare_api_returns_finding_changes_and_summary(tmp_path):
    client, session_local = make_test_client(tmp_path)
    try:
        create_comparable_scans(session_local)

        response = client.get("/api/scans/scan_target/compare?base_scan_id=scan_base")

        assert response.status_code == 200
        body = response.json()
        assert body["base_scan_id"] == "scan_base"
        assert body["target_scan_id"] == "scan_target"
        assert [finding["id"] for finding in body["new_findings"]] == ["target_new"]
        assert [finding["id"] for finding in body["resolved_findings"]] == ["base_resolved"]
        assert [finding["id"] for finding in body["persistent_findings"]] == [
            "target_persistent"
        ]
        assert body["summary"]["new_findings"] == {
            "total": 1,
            "by_severity": {"high": 1},
            "by_category": {"secret": 1},
        }
        assert body["summary"]["resolved_findings"] == {
            "total": 1,
            "by_severity": {"medium": 1},
            "by_category": {"cve": 1},
        }
        assert body["summary"]["persistent_findings"] == {
            "total": 1,
            "by_severity": {"critical": 1},
            "by_category": {"sast": 1},
        }
    finally:
        app.dependency_overrides.clear()


def test_scan_compare_api_returns_404_for_missing_target_scan(tmp_path):
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
            create_scan(
                db,
                scan_id="scan_base",
                project_id="project_001",
                project_name="demo",
                target_path="C:/AI/projects/demo",
                status="completed",
            )
        finally:
            db.close()

        response = client.get("/api/scans/missing/compare?base_scan_id=scan_base")

        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"
    finally:
        app.dependency_overrides.clear()


def test_scan_compare_api_returns_404_for_missing_base_scan(tmp_path):
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
            create_scan(
                db,
                scan_id="scan_target",
                project_id="project_001",
                project_name="demo",
                target_path="C:/AI/projects/demo",
                status="completed",
            )
        finally:
            db.close()

        response = client.get("/api/scans/scan_target/compare?base_scan_id=missing")

        assert response.status_code == 404
        assert response.json()["detail"] == "Base scan not found"
    finally:
        app.dependency_overrides.clear()


def test_scan_compare_api_returns_400_for_different_projects(tmp_path):
    client, session_local = make_test_client(tmp_path)
    try:
        db = session_local()
        try:
            create_project(
                db,
                project_id="project_base",
                name="base",
                root_path="C:/AI/projects/base",
            )
            create_project(
                db,
                project_id="project_target",
                name="target",
                root_path="C:/AI/projects/target",
            )
            create_scan(
                db,
                scan_id="scan_base",
                project_id="project_base",
                project_name="base",
                target_path="C:/AI/projects/base",
                status="completed",
            )
            create_scan(
                db,
                scan_id="scan_target",
                project_id="project_target",
                project_name="target",
                target_path="C:/AI/projects/target",
                status="completed",
            )
        finally:
            db.close()

        response = client.get("/api/scans/scan_target/compare?base_scan_id=scan_base")

        assert response.status_code == 400
        assert "same project_id" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()
