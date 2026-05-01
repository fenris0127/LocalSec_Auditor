from __future__ import annotations

from collections import Counter
from collections.abc import Generator
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.crud.finding import list_findings_by_scan
from app.db.base import Base
from app.db.database import get_db_session
from app.main import app
from app.orchestrator import hermes
from app.reports import generator
from app.scanners.runner import CommandResult


SECRET_VALUES = [
    "sk_test_1234567890",
    "-----BEGIN PRIVATE KEY-----FAKE-----END PRIVATE KEY-----",
]


def _make_client(tmp_path):
    db_path = tmp_path / "integration.db"
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


def _fixture_text(name: str) -> str:
    return (Path(__file__).parent / "fixtures" / name).read_text(encoding="utf-8")


def test_mvp_scan_to_findings_and_report_with_mock_scanners(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    target_path = workspace / "demo"
    target_path.mkdir(parents=True)
    monkeypatch.setenv("LOCALSC_WORKSPACE", str(workspace))

    client, session_local = _make_client(tmp_path)
    monkeypatch.setattr(hermes, "SessionLocal", session_local)
    monkeypatch.setattr(generator, "SessionLocal", session_local)
    monkeypatch.setattr("app.services.scan_dirs.PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(generator, "PROJECT_ROOT", tmp_path)

    semgrep_json = _fixture_text("sample_semgrep.json")
    gitleaks_json = _fixture_text("sample_gitleaks.json")
    trivy_json = _fixture_text("sample_trivy.json")

    scanner_calls: list[tuple[str, str, str]] = []

    def fake_semgrep(target: str, output_path: str, timeout=None) -> CommandResult:
        scanner_calls.append(("semgrep", target, output_path))
        return CommandResult(stdout=semgrep_json, stderr="", exit_code=0)

    def fake_gitleaks(target: str, output_path: str, timeout=None) -> CommandResult:
        scanner_calls.append(("gitleaks", target, output_path))
        return CommandResult(stdout=gitleaks_json, stderr="", exit_code=0)

    def fake_trivy(target: str, output_path: str, timeout=None) -> CommandResult:
        scanner_calls.append(("trivy", target, output_path))
        return CommandResult(stdout=trivy_json, stderr="", exit_code=0)

    monkeypatch.setattr(hermes, "run_semgrep", fake_semgrep)
    monkeypatch.setattr(hermes, "run_gitleaks", fake_gitleaks)
    monkeypatch.setattr(hermes, "run_trivy_fs", fake_trivy)

    try:
        create_response = client.post(
            "/api/scans",
            json={
                "project_name": "demo",
                "target_path": str(target_path),
                "scan_types": ["semgrep", "gitleaks", "trivy"],
                "llm_enabled": True,
                "run_immediately": True,
            },
        )

        assert create_response.status_code == 200
        created = create_response.json()
        scan_id = created["scan_id"]
        assert created["status"] == "completed"

        assert [call[0] for call in scanner_calls] == ["trivy", "semgrep", "gitleaks"]
        assert {call[1] for call in scanner_calls} == {str(target_path)}

        raw_dir = tmp_path / "data" / "scans" / scan_id / "raw"
        assert (raw_dir / "semgrep.json").is_file()
        assert (raw_dir / "gitleaks.json").is_file()
        assert (raw_dir / "trivy.json").is_file()

        findings_response = client.get(f"/api/scans/{scan_id}/findings")
        assert findings_response.status_code == 200
        findings = findings_response.json()
        assert Counter(finding["scanner"] for finding in findings) == Counter(
            {"semgrep": 4, "gitleaks": 2, "trivy": 2}
        )
        assert any(finding["title"] == "Secret detected: generic-api-key" for finding in findings)
        assert any(
            finding["title"] == "Prototype Pollution in lodash (fixed: 4.17.21)"
            for finding in findings
        )

        serialized_findings = str(findings)
        for secret_value in SECRET_VALUES:
            assert secret_value not in serialized_findings

        db = session_local()
        try:
            persisted_findings = list_findings_by_scan(db, scan_id)
            serialized_db_findings = "\n".join(
                f"{finding.title}|{finding.file_path}|{finding.component}|{finding.cve}|{finding.cwe}"
                for finding in persisted_findings
            )
        finally:
            db.close()

        for secret_value in SECRET_VALUES:
            assert secret_value not in serialized_db_findings

        report_response = client.post(f"/api/scans/{scan_id}/report")
        assert report_response.status_code == 200
        report = report_response.json()["content"]
        assert "# LocalSec Auditor Report" in report
        assert "- Total Findings: 8" in report
        assert "Secret detected: generic-api-key" in report
        assert "Prototype Pollution in lodash (fixed: 4.17.21)" in report
        for secret_value in SECRET_VALUES:
            assert secret_value not in report
    finally:
        app.dependency_overrides.clear()
