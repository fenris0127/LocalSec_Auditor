from datetime import datetime
from uuid import uuid4

import pytest
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


def test_generate_markdown_report_includes_cce_configuration_section(monkeypatch):
    scan_id = f"report_cce_test_{uuid4().hex}"
    session_local = make_session_local()
    files: dict[str, str] = {}
    monkeypatch.setattr(generator, "SessionLocal", session_local)
    monkeypatch.setattr(generator, "retrieve_context_for_finding", lambda finding, **kwargs: [])
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
            finding_id="finding_cce",
            scan_id=scan_id,
            category="cce",
            scanner="openscap",
            severity="high",
            title="SSH root login is enabled",
            status="open",
            rule_id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
            cce_id="CCE-80801-6",
            current_value="PermitRootLogin yes",
            expected_value="PermitRootLogin no",
            raw_json_path=f"data/scans/{scan_id}/raw/openscap.xml",
        )
        create_finding(
            db,
            finding_id="finding_config",
            scan_id=scan_id,
            category="config",
            scanner="lynis",
            severity="medium",
            title="Firewall is not enabled",
            status="open",
            rule_id="lynis:warning",
            raw_json_path=f"data/scans/{scan_id}/raw/lynis.txt",
        )
        create_finding(
            db,
            finding_id="finding_sast",
            scan_id=scan_id,
            category="sast",
            scanner="semgrep",
            severity="low",
            title="SAST finding outside CCE section",
            status="open",
        )
    finally:
        db.close()

    report_path = generator.generate_markdown_report(scan_id)
    report = report_path.read_text(encoding="utf-8")

    assert "## CCE / System Configuration Findings" in report
    assert "SSH root login is enabled" in report
    assert "Firewall is not enabled" in report
    assert "- Rule ID: xccdf_org.ssgproject.content_rule_sshd_disable_root_login" in report
    assert "- CCE ID: CCE-80801-6" in report
    assert "- Current Value: PermitRootLogin yes" in report
    assert "- Expected Value: PermitRootLogin no" in report
    assert "Rollback / Verification Guidance" in report
    assert "Rollback: save the original setting value" in report
    assert "Verification: re-run the same scanner/profile" in report
    assert "This section is for review only. It does not change system settings." in report
    assert "automatic remediation" not in report.lower()
    assert "--remediate" not in report


def test_generate_html_report_creates_html_from_markdown_and_masks_secrets(monkeypatch):
    scan_id = f"report_html_test_{uuid4().hex}"
    secret_value = "sk_test_html_report_secret_value"
    session_local = make_session_local()
    files: dict[str, str] = {}
    monkeypatch.setattr(generator, "SessionLocal", session_local)
    monkeypatch.setattr(generator, "retrieve_context_for_finding", lambda finding, **kwargs: [])
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
            category="secret",
            scanner="gitleaks",
            severity="high",
            title="Secret detected: generic-api-key",
            status="open",
            file_path=".env",
            line=1,
            llm_summary=f"Rotate leaked token {secret_value}.",
        )
    finally:
        db.close()

    report_path = generator.generate_html_report(scan_id)
    report = report_path.read_text(encoding="utf-8")

    assert str(report_path) == f"data/scans/{scan_id}/reports/report.html"
    assert report_path.is_file()
    assert "<!doctype html>" in report
    assert "<h1>LocalSec Auditor Report:" in report
    assert "Secret detected: generic-api-key" in report
    assert 'class="severity severity-high"' in report
    assert secret_value not in report
    assert "[REDACTED_SECRET]" in report


def test_generate_pdf_report_uses_html_report_and_masks_secrets(monkeypatch):
    scan_id = f"report_pdf_test_{uuid4().hex}"
    secret_value = "sk_test_pdf_report_secret_value"
    session_local = make_session_local()
    files: dict[str, str] = {}
    captured: dict[str, str] = {}
    monkeypatch.setattr(generator, "SessionLocal", session_local)
    monkeypatch.setattr(generator, "retrieve_context_for_finding", lambda finding, **kwargs: [])
    monkeypatch.setattr(
        generator,
        "create_scan_dirs",
        lambda scan_id: {
            "raw": MemoryPath(f"data/scans/{scan_id}/raw", files),
            "normalized": MemoryPath(f"data/scans/{scan_id}/normalized", files),
            "reports": MemoryPath(f"data/scans/{scan_id}/reports", files),
        },
    )

    def fake_convert_html_to_pdf(html, output_path):
        captured["html"] = html
        output_path.write_text("%PDF-FAKE%", encoding="utf-8")

    monkeypatch.setattr(generator, "_convert_html_to_pdf", fake_convert_html_to_pdf)

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
            finding_id="finding_secret",
            scan_id=scan_id,
            category="secret",
            scanner="gitleaks",
            severity="high",
            title="Secret detected: generic-api-key",
            status="open",
            file_path=".env",
            line=1,
            llm_summary=f"Rotate leaked token {secret_value}.",
        )
    finally:
        db.close()

    report_path = generator.generate_pdf_report(scan_id)

    assert str(report_path) == f"data/scans/{scan_id}/reports/report.pdf"
    assert report_path.is_file()
    assert report_path.read_text(encoding="utf-8") == "%PDF-FAKE%"
    assert "<!doctype html>" in captured["html"]
    assert "Secret detected: generic-api-key" in captured["html"]
    assert secret_value not in captured["html"]
    assert "[REDACTED_SECRET]" in captured["html"]


def test_generate_pdf_report_raises_clear_error_when_conversion_fails(monkeypatch):
    scan_id = f"report_pdf_error_test_{uuid4().hex}"
    session_local = make_session_local()
    files: dict[str, str] = {}
    monkeypatch.setattr(generator, "SessionLocal", session_local)
    monkeypatch.setattr(generator, "retrieve_context_for_finding", lambda finding, **kwargs: [])
    monkeypatch.setattr(
        generator,
        "create_scan_dirs",
        lambda scan_id: {
            "raw": MemoryPath(f"data/scans/{scan_id}/raw", files),
            "normalized": MemoryPath(f"data/scans/{scan_id}/normalized", files),
            "reports": MemoryPath(f"data/scans/{scan_id}/reports", files),
        },
    )

    def fake_convert_html_to_pdf(html, output_path):
        raise generator.ReportExportError("PDF export failed: converter unavailable")

    monkeypatch.setattr(generator, "_convert_html_to_pdf", fake_convert_html_to_pdf)

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

    with pytest.raises(generator.ReportExportError, match="PDF export failed"):
        generator.generate_pdf_report(scan_id)
