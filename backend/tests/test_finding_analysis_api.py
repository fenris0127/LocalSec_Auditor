from collections.abc import Generator
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crud.finding import create_finding, get_finding
from app.crud.scan import create_scan
from app.db.base import Base
from app.db.database import get_db_session
from app.llm.client import OllamaError
from app.main import app


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


def seed_finding(session_local, *, finding_id: str = "finding_001") -> None:
    db = session_local()
    try:
        create_scan(
            db,
            scan_id="scan_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="completed",
        )
        create_finding(
            db,
            finding_id=finding_id,
            scan_id="scan_001",
            category="sast",
            scanner="semgrep",
            severity="high",
            title="Potential SQL injection",
            status="open",
            file_path="src/user.py",
            line=42,
            cwe="CWE-89",
            raw_json_path="data/scans/scan_001/raw/semgrep.json",
        )
    finally:
        db.close()


def test_analyze_finding_api_stores_llm_summary():
    client, session_local = make_client()
    seed_finding(session_local)

    def fake_generate(prompt: str) -> str:
        assert "scanner: semgrep" in prompt
        assert "Potential SQL injection" in prompt
        return "LLM analysis summary"

    try:
        with patch("app.api.findings.generate", side_effect=fake_generate) as generate_mock:
            response = client.post("/api/findings/finding_001/analyze")

        assert response.status_code == 200
        assert response.json() == {"llm_summary": "LLM analysis summary"}
        generate_mock.assert_called_once()

        db = session_local()
        try:
            finding = get_finding(db, "finding_001")
        finally:
            db.close()

        assert finding is not None
        assert finding.llm_summary == "LLM analysis summary"
    finally:
        app.dependency_overrides.clear()


def test_analyze_finding_api_returns_404_for_missing_finding():
    client, _ = make_client()
    try:
        response = client.post("/api/findings/missing/analyze")

        assert response.status_code == 404
        assert response.json()["detail"] == "Finding not found"
    finally:
        app.dependency_overrides.clear()


def test_analyze_finding_api_returns_502_when_ollama_fails():
    client, session_local = make_client()
    seed_finding(session_local)

    try:
        with patch(
            "app.api.findings.generate",
            side_effect=OllamaError("connection failed"),
        ):
            response = client.post("/api/findings/finding_001/analyze")

        assert response.status_code == 502
        assert response.json()["detail"] == "Ollama analysis failed"

        db = session_local()
        try:
            finding = get_finding(db, "finding_001")
        finally:
            db.close()

        assert finding is not None
        assert finding.llm_summary is None
    finally:
        app.dependency_overrides.clear()
