import json
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.crud.finding import create_finding, list_findings_by_scan
from app.crud.scan import create_scan
from app.crud.task import create_task
from app.crud.task_log import create_task_log
from app.db.base import Base
from app.llm.prompts import build_finding_analysis_prompt
from app.normalizers.gitleaks import normalize_gitleaks
from app.reports import generator


SAMPLE_SECRET = "sk_test_regression_secret_value_1234567890abcdef"


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


def serialized_model_values(model) -> str:
    return json.dumps(
        {
            column.name: getattr(model, column.name)
            for column in model.__table__.columns
        },
        default=str,
        ensure_ascii=False,
        sort_keys=True,
    )


def test_secret_raw_value_does_not_reach_normalizer_db_prompt_report_or_logs(monkeypatch):
    scan_id = "secret_safety_regression_scan"
    raw_json_path = f"data/scans/{scan_id}/raw/gitleaks.json"
    raw_gitleaks_payload = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API key",
            "File": ".env",
            "StartLine": 3,
            "Secret": SAMPLE_SECRET,
            "Match": f"API_KEY={SAMPLE_SECRET}",
        }
    ]
    monkeypatch.setattr(
        "app.normalizers.gitleaks.Path.read_text",
        lambda self, encoding="utf-8": json.dumps(raw_gitleaks_payload),
    )

    normalized_findings = normalize_gitleaks(raw_json_path, scan_id)

    assert len(normalized_findings) == 1
    assert SAMPLE_SECRET not in normalized_findings[0].model_dump_json()

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
            created_at=datetime(2026, 5, 6, 10, 0, 0),
        )
        create_task(
            db,
            task_id="task_gitleaks",
            scan_id=scan_id,
            task_type="scanner",
            tool_name="gitleaks",
            status="completed",
        )

        normalized = normalized_findings[0]
        stored_finding = create_finding(
            db,
            finding_id=normalized.id,
            scan_id=normalized.scan_id,
            category=normalized.category,
            scanner=normalized.scanner,
            severity=normalized.severity,
            title=normalized.title,
            status=normalized.status,
            rule_id=normalized.rule_id,
            file_path=normalized.file_path,
            line=normalized.line,
            component=normalized.component,
            cve=normalized.cve,
            cwe=normalized.cwe,
            raw_json_path=normalized.raw_json_path,
        )
        log = create_task_log(
            db,
            log_id="task_log_secret_regression",
            task_id="task_gitleaks",
            level="warning",
            message=f"gitleaks stderr included {SAMPLE_SECRET}",
        )

        db_findings = list_findings_by_scan(db, scan_id)
        db_payload = "\n".join(serialized_model_values(finding) for finding in db_findings)
    finally:
        db.close()

    prompt = build_finding_analysis_prompt(normalized_findings[0])
    report_path = generator.generate_markdown_report(scan_id)
    report = report_path.read_text(encoding="utf-8")

    assert SAMPLE_SECRET not in serialized_model_values(stored_finding)
    assert SAMPLE_SECRET not in db_payload
    assert SAMPLE_SECRET not in prompt
    assert SAMPLE_SECRET not in report
    assert SAMPLE_SECRET not in log.message
    assert "[REDACTED_SECRET]" in log.message
    assert "Secret detected: generic-api-key" in report
