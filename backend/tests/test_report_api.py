from collections.abc import Generator
from datetime import datetime
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crud.scan import create_scan
from app.db.base import Base
from app.db.database import get_db_session
from app.main import app


class MemoryPath:
    def __init__(self, path: str, files: dict[str, str]):
        self.path = path
        self.files = files

    def read_text(self, encoding: str = "utf-8") -> str:
        return self.files[self.path]

    def is_file(self) -> bool:
        return self.path in self.files

    def __str__(self) -> str:
        return self.path


def make_client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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


def seed_scan(session_local, scan_id: str = "scan_001") -> None:
    db = session_local()
    try:
        create_scan(
            db,
            scan_id=scan_id,
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="completed",
            created_at=datetime(2026, 4, 30, 10, 0, 0),
        )
    finally:
        db.close()


def test_create_report_api_returns_report_content():
    client, session_local = make_client()
    seed_scan(session_local)
    files = {"data/scans/scan_001/reports/report.md": "# LocalSec Auditor Report\n"}
    report_path = MemoryPath("data/scans/scan_001/reports/report.md", files)

    try:
        with patch("app.api.scans.generate_markdown_report", return_value=report_path) as generator_mock:
            response = client.post("/api/scans/scan_001/report")

        assert response.status_code == 200
        assert response.json() == {
            "report_path": "data/scans/scan_001/reports/report.md",
            "content": "# LocalSec Auditor Report\n",
        }
        generator_mock.assert_called_once_with("scan_001")
    finally:
        app.dependency_overrides.clear()


def test_get_report_api_returns_report_content():
    client, session_local = make_client()
    seed_scan(session_local)
    files = {"data/scans/scan_001/reports/report.md": "# Saved Report\n"}
    report_path = MemoryPath("data/scans/scan_001/reports/report.md", files)

    try:
        with patch("app.api.scans.get_markdown_report_path", return_value=report_path):
            response = client.get("/api/scans/scan_001/report")

        assert response.status_code == 200
        assert response.json() == {
            "report_path": "data/scans/scan_001/reports/report.md",
            "content": "# Saved Report\n",
        }
    finally:
        app.dependency_overrides.clear()


def test_report_apis_return_404_for_missing_scan():
    client, _ = make_client()
    try:
        post_response = client.post("/api/scans/missing/report")
        get_response = client.get("/api/scans/missing/report")

        assert post_response.status_code == 404
        assert post_response.json()["detail"] == "Scan not found"
        assert get_response.status_code == 404
        assert get_response.json()["detail"] == "Scan not found"
    finally:
        app.dependency_overrides.clear()


def test_get_report_api_returns_404_when_report_is_missing():
    client, session_local = make_client()
    seed_scan(session_local)
    report_path = MemoryPath("data/scans/scan_001/reports/report.md", {})

    try:
        with patch("app.api.scans.get_markdown_report_path", return_value=report_path):
            response = client.get("/api/scans/scan_001/report")

        assert response.status_code == 404
        assert response.json()["detail"] == "Report not found"
    finally:
        app.dependency_overrides.clear()
