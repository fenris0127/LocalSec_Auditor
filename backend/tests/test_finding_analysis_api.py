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
from app.rag.vector_store import VectorSearchResult


GOOD_SAST_RESPONSE = """
1. 요약
Scanner evidence reports a potential SQL injection finding in src/user.py.

2. 위험한 이유
Unsafe query construction can expose application data if the scanner finding is confirmed.

3. 조치 방법
Use parameterized queries and validate the request input near the reported line.

4. 검증 방법
Verify by rerunning Semgrep and reviewing the affected query construction.

5. 오탐 가능성
False positive likelihood is possible and should be checked against the actual data flow.
""".strip()


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
        assert "참고 근거" not in prompt
        return GOOD_SAST_RESPONSE

    try:
        with (
            patch("app.api.findings.retrieve_context_for_finding", return_value=[]),
            patch("app.api.findings.generate", side_effect=fake_generate) as generate_mock,
        ):
            response = client.post("/api/findings/finding_001/analyze")

        assert response.status_code == 200
        assert response.json() == {"llm_summary": GOOD_SAST_RESPONSE}
        generate_mock.assert_called_once()

        db = session_local()
        try:
            finding = get_finding(db, "finding_001")
        finally:
            db.close()

        assert finding is not None
        assert finding.llm_summary == GOOD_SAST_RESPONSE
    finally:
        app.dependency_overrides.clear()


def test_analyze_finding_api_includes_rag_context_in_prompt():
    client, session_local = make_client()
    seed_finding(session_local)
    secret_value = "sk_test_rag_context_secret_value_1234567890abcdef"
    rag_context = [
        VectorSearchResult(
            id="chunk_001",
            content=f"OWASP recommends parameterized queries. Do not expose {secret_value}.",
            metadata={
                "title": "OWASP SQL Injection",
                "source_path": "docs/owasp/sql-injection.md",
                "chunk_index": 1,
                "summary": "Use parameterized queries for SQL injection remediation.",
            },
            score=0.95,
        )
    ]

    def fake_generate(prompt: str) -> str:
        assert "참고 근거" in prompt
        assert "OWASP SQL Injection" in prompt
        assert "docs/owasp/sql-injection.md" in prompt
        assert "Use parameterized queries for SQL injection remediation." in prompt
        assert "OWASP recommends parameterized queries." in prompt
        assert secret_value not in prompt
        assert "[REDACTED_SECRET]" in prompt
        return GOOD_SAST_RESPONSE

    try:
        with (
            patch("app.api.findings.retrieve_context_for_finding", return_value=rag_context) as retrieve_mock,
            patch("app.api.findings.generate", side_effect=fake_generate),
        ):
            response = client.post("/api/findings/finding_001/analyze")

        assert response.status_code == 200
        retrieve_mock.assert_called_once()

        db = session_local()
        try:
            finding = get_finding(db, "finding_001")
        finally:
            db.close()

        assert finding is not None
        assert finding.llm_summary == GOOD_SAST_RESPONSE
    finally:
        app.dependency_overrides.clear()


def test_analyze_finding_api_keeps_existing_behavior_when_rag_retrieval_fails():
    client, session_local = make_client()
    seed_finding(session_local)

    def fake_generate(prompt: str) -> str:
        assert "참고 근거" not in prompt
        return GOOD_SAST_RESPONSE

    try:
        with (
            patch(
                "app.api.findings.retrieve_context_for_finding",
                side_effect=RuntimeError("rag unavailable"),
            ),
            patch("app.api.findings.generate", side_effect=fake_generate),
        ):
            response = client.post("/api/findings/finding_001/analyze")

        assert response.status_code == 200
        assert response.json() == {"llm_summary": GOOD_SAST_RESPONSE}
    finally:
        app.dependency_overrides.clear()


def test_analyze_finding_api_rejects_evaluator_failure_without_saving():
    client, session_local = make_client()
    seed_finding(session_local)
    bad_response = GOOD_SAST_RESPONSE + "\nAlso related: CVE-2099-9999"

    try:
        with (
            patch("app.api.findings.retrieve_context_for_finding", return_value=[]),
            patch("app.api.findings.generate", return_value=bad_response),
        ):
            response = client.post("/api/findings/finding_001/analyze")

        assert response.status_code == 422
        assert response.json()["detail"]["message"] == "LLM analysis failed safety evaluation"
        assert "contains CVE not present in input_finding" in response.json()["detail"]["failures"][0]

        db = session_local()
        try:
            finding = get_finding(db, "finding_001")
        finally:
            db.close()

        assert finding is not None
        assert finding.llm_summary is None
    finally:
        app.dependency_overrides.clear()


def test_analyze_finding_api_rejects_secret_leak_without_saving():
    client, session_local = make_client()
    seed_finding(session_local)
    secret_value = "sk_test_analysis_secret_value_1234567890abcdef"
    bad_response = GOOD_SAST_RESPONSE + f"\nLeaked secret: {secret_value}"

    try:
        with (
            patch("app.api.findings.retrieve_context_for_finding", return_value=[]),
            patch("app.api.findings.generate", return_value=bad_response),
        ):
            response = client.post("/api/findings/finding_001/analyze")

        assert response.status_code == 422
        assert "contains raw secret-like value" in response.json()["detail"]["failures"]
        assert secret_value not in str(response.json())

        db = session_local()
        try:
            finding = get_finding(db, "finding_001")
        finally:
            db.close()

        assert finding is not None
        assert finding.llm_summary is None
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
        with (
            patch("app.api.findings.retrieve_context_for_finding", return_value=[]),
            patch(
                "app.api.findings.generate",
                side_effect=OllamaError("connection failed"),
            ),
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
