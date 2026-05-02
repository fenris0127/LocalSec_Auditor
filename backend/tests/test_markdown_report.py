from datetime import datetime
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.crud.finding import create_finding
from app.crud.scan import create_scan
from app.db.base import Base
from app.reports import generator
from app.rag.vector_store import VectorSearchResult


class MemoryPath:
    def __init__(self, path: str, files: dict[str, str]):
        self.path = path
        self.files = files

    def __truediv__(self, child: str) -> "MemoryPath":
        return MemoryPath(f"{self.path}/{child}", self.files)

    def write_text(self, content: str, encoding: str = "utf-8") -> int:
        self.files[self.path] = content
        return len(content)

    def read_text(self, encoding: str = "utf-8") -> str:
        return self.files[self.path]

    def is_file(self) -> bool:
        return self.path in self.files

    def __str__(self) -> str:
        return self.path


def make_session_local():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def test_generate_markdown_report_creates_report_with_stats_and_llm_summary(monkeypatch):
    scan_id = f"report_test_{uuid4().hex}"
    secret_value = "ghp_super_secret_token_value"
    secret_api_key = "sk_test_report_secret_value"
    session_local = make_session_local()
    files: dict[str, str] = {}
    monkeypatch.setattr(generator, "SessionLocal", session_local)
    monkeypatch.setattr(
        generator,
        "create_scan_dirs",
        lambda scan_id: {
            "raw": MemoryPath(f"data/scans/{scan_id}/raw", files),
            "normalized": MemoryPath(f"data/scans/{scan_id}/normalized", files),
            "reports": MemoryPath(f"data/scans/{scan_id}/reports", files),
        },
    )

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
        create_finding(
            db,
            finding_id="finding_high",
            scan_id=scan_id,
            category="sast",
            scanner="semgrep",
            severity="high",
            title="Potential SQL injection",
            status="open",
            file_path="src/user.py",
            line=42,
            cwe="CWE-89",
            raw_json_path=f"data/scans/{scan_id}/raw/semgrep.json",
            llm_summary="Validate the query construction and use parameterized statements.",
        )
        create_finding(
            db,
            finding_id="finding_medium",
            scan_id=scan_id,
            category="cve",
            scanner="trivy",
            severity="medium",
            title="Vulnerable dependency",
            status="open",
            component="demo-lib",
            cve="CVE-2026-0001",
            raw_json_path=f"data/scans/{scan_id}/raw/trivy.json",
        )
        create_finding(
            db,
            finding_id="finding_secret",
            scan_id=scan_id,
            category="secret",
            scanner="gitleaks",
            severity="high",
            title="Secret detected: generic-api-key",
            status="open",
            file_path=".env",
            line=1,
            raw_json_path=f"data/scans/{scan_id}/raw/gitleaks.json",
            llm_summary=f"Rotate leaked token {secret_api_key} immediately.",
        )
    finally:
        db.close()

    report_path = generator.generate_markdown_report(scan_id)
    report = report_path.read_text(encoding="utf-8")

    assert str(report_path) == f"data/scans/{scan_id}/reports/report.md"
    assert report_path.is_file()
    assert "# LocalSec Auditor Report" in report
    assert "- Project: demo" in report
    assert "- Total Findings: 3" in report
    assert "- high: 2" in report
    assert "- medium: 1" in report
    assert "- sast: 1" in report
    assert "- cve: 1" in report
    assert "- secret: 1" in report
    assert "## Priority List" in report
    assert "## Finding Details" in report
    assert "Validate the query construction and use parameterized statements." in report
    assert "Secret detected: generic-api-key" in report
    assert secret_value not in report
    assert secret_api_key not in report
    assert "[REDACTED_SECRET]" in report


def test_generate_markdown_report_includes_rag_reference_documents(monkeypatch):
    scan_id = f"report_rag_test_{uuid4().hex}"
    secret_value = "ghp_rag_report_secret_value"
    session_local = make_session_local()
    files: dict[str, str] = {}
    monkeypatch.setattr(generator, "SessionLocal", session_local)
    monkeypatch.setattr(
        generator,
        "create_scan_dirs",
        lambda scan_id: {
            "raw": MemoryPath(f"data/scans/{scan_id}/raw", files),
            "normalized": MemoryPath(f"data/scans/{scan_id}/normalized", files),
            "reports": MemoryPath(f"data/scans/{scan_id}/reports", files),
        },
    )

    def fake_retrieve_context_for_finding(finding, **kwargs):
        if finding.id == "finding_with_context":
            return [
                VectorSearchResult(
                    id="chunk_1",
                    content=(
                        "OWASP SQL injection guidance recommends parameterized queries. "
                        f"Do not expose {secret_value} in reports."
                    ),
                    metadata={
                        "title": "OWASP SQL Injection",
                        "source_path": "docs/owasp/sql-injection.md",
                        "chunk_index": 2,
                        "summary": (
                            "Use parameterized queries for SQL injection remediation. "
                            f"Remove exposed token {secret_value}."
                        ),
                    },
                    score=0.91,
                )
            ]
        return []

    monkeypatch.setattr(
        generator,
        "retrieve_context_for_finding",
        fake_retrieve_context_for_finding,
    )

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
        create_finding(
            db,
            finding_id="finding_with_context",
            scan_id=scan_id,
            category="sast",
            scanner="semgrep",
            severity="high",
            title="Potential SQL injection",
            status="open",
            cwe="CWE-89",
        )
        create_finding(
            db,
            finding_id="finding_without_context",
            scan_id=scan_id,
            category="cve",
            scanner="trivy",
            severity="medium",
            title="Vulnerable dependency",
            status="open",
            component="demo-lib",
            cve="CVE-2026-0001",
        )
    finally:
        db.close()

    report_path = generator.generate_markdown_report(scan_id)
    report = report_path.read_text(encoding="utf-8")

    assert "**근거 문서**" in report
    assert "- Source: OWASP SQL Injection" in report
    assert "- Path: docs/owasp/sql-injection.md" in report
    assert "- Chunk: 2" in report
    assert "- Summary: Use parameterized queries for SQL injection remediation." in report
    assert "근거 문서 없음" in report
    assert secret_value not in report
    assert "[REDACTED_SECRET]" in report
