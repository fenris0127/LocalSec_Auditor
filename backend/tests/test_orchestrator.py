from collections import Counter
from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.finding import list_findings_by_scan
from app.crud.scan import create_scan, get_scan
from app.crud.task import create_task, list_tasks_by_scan
from app.db.base import Base
from app.orchestrator import hermes
from app.scanners.runner import CommandResult


def make_session(tmp_path):
    db_path = tmp_path / "orchestrator.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def _configure_session(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'orchestrator.db').as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(hermes, "SessionLocal", session_local)
    monkeypatch.setattr("app.services.scan_dirs.PROJECT_ROOT", tmp_path)
    return session_local


def test_run_scan_persists_findings_and_updates_task_statuses(monkeypatch, tmp_path):
    session_local = _configure_session(monkeypatch, tmp_path)
    db = session_local()
    try:
        scan = create_scan(
            db,
            scan_id="scan_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="queued",
            created_at=datetime(2026, 4, 30, 10, 0, 0),
        )
        create_task(db, task_id="task_semgrep", scan_id=scan.id, task_type="scanner", tool_name="semgrep", status="queued")
        create_task(db, task_id="task_gitleaks", scan_id=scan.id, task_type="scanner", tool_name="gitleaks", status="queued")
        create_task(db, task_id="task_trivy", scan_id=scan.id, task_type="scanner", tool_name="trivy", status="queued")
    finally:
        db.close()

    semgrep_json = (Path(__file__).parent / "fixtures" / "sample_semgrep.json").read_text(encoding="utf-8")
    gitleaks_json = (Path(__file__).parent / "fixtures" / "sample_gitleaks.json").read_text(encoding="utf-8")
    trivy_json = (Path(__file__).parent / "fixtures" / "sample_trivy.json").read_text(encoding="utf-8")

    monkeypatch.setattr(hermes, "run_semgrep", lambda target_path, output_path, timeout=None: CommandResult(stdout=semgrep_json, stderr="", exit_code=0))
    monkeypatch.setattr(hermes, "run_gitleaks", lambda target_path, output_path, timeout=None: CommandResult(stdout=gitleaks_json, stderr="", exit_code=0))
    monkeypatch.setattr(hermes, "run_trivy_fs", lambda target_path, output_path, timeout=None: CommandResult(stdout=trivy_json, stderr="", exit_code=0))

    hermes.run_scan("scan_001")

    db = session_local()
    try:
        scan = get_scan(db, "scan_001")
        tasks = list_tasks_by_scan(db, "scan_001")
        findings = list_findings_by_scan(db, "scan_001")
    finally:
        db.close()

    assert scan is not None
    assert scan.status == "completed"
    assert scan.started_at is not None
    assert scan.finished_at is not None
    assert {task.status for task in tasks} == {"completed"}
    assert all(task.started_at is not None for task in tasks)
    assert all(task.finished_at is not None for task in tasks)
    assert Counter(finding.scanner for finding in findings) == Counter({"semgrep": 4, "gitleaks": 2, "trivy": 2})
    assert any(finding.title == "Secret detected: generic-api-key" for finding in findings)
    assert any(finding.title == "Prototype Pollution in lodash (fixed: 4.17.21)" for finding in findings)

    raw_dir = tmp_path / "data" / "scans" / "scan_001" / "raw"
    assert (raw_dir / "semgrep.json").is_file()
    assert (raw_dir / "gitleaks.json").is_file()
    assert (raw_dir / "trivy.json").is_file()


def test_run_scan_executes_syft_then_grype_and_persists_grype_findings(monkeypatch, tmp_path):
    session_local = _configure_session(monkeypatch, tmp_path)
    db = session_local()
    try:
        scan = create_scan(
            db,
            scan_id="scan_sbom",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="queued",
            created_at=datetime(2026, 4, 30, 10, 0, 0),
        )
        create_task(
            db,
            task_id="task_syft",
            scan_id=scan.id,
            task_type="scanner",
            tool_name="syft",
            status="queued",
        )
        create_task(
            db,
            task_id="task_grype",
            scan_id=scan.id,
            task_type="scanner",
            tool_name="grype",
            status="queued",
        )
    finally:
        db.close()

    grype_json = (Path(__file__).parent / "fixtures" / "sample_grype.json").read_text(encoding="utf-8")
    calls: list[tuple[str, str, str]] = []

    def fake_syft(target_path: str, output_path: str, timeout=None) -> CommandResult:
        calls.append(("syft", target_path, output_path))
        return CommandResult(stdout='{"artifacts":[]}', stderr="", exit_code=0)

    def fake_grype(sbom_path: str, output_path: str, timeout=None) -> CommandResult:
        calls.append(("grype", sbom_path, output_path))
        return CommandResult(stdout=grype_json, stderr="", exit_code=0)

    monkeypatch.setattr(hermes, "run_syft", fake_syft)
    monkeypatch.setattr(hermes, "run_grype_sbom", fake_grype)

    hermes.run_scan("scan_sbom")

    db = session_local()
    try:
        scan = get_scan(db, "scan_sbom")
        tasks = list_tasks_by_scan(db, "scan_sbom")
        findings = list_findings_by_scan(db, "scan_sbom")
    finally:
        db.close()

    raw_dir = tmp_path / "data" / "scans" / "scan_sbom" / "raw"
    syft_path = raw_dir / "syft-sbom.json"
    grype_path = raw_dir / "grype.json"

    assert calls == [
        ("syft", "C:/AI/projects/demo", str(syft_path)),
        ("grype", str(syft_path), str(grype_path)),
    ]
    assert syft_path.is_file()
    assert grype_path.is_file()
    assert scan is not None
    assert scan.status == "completed"
    assert {task.status for task in tasks} == {"completed"}
    assert Counter(finding.scanner for finding in findings) == Counter({"grype": 2})
    assert {finding.cve for finding in findings} == {"CVE-2026-3000", "CVE-2026-4000"}
    assert {finding.component for finding in findings} == {"lodash", "axios"}


def test_run_scan_marks_failed_task_and_scan_failed(monkeypatch, tmp_path):
    session_local = _configure_session(monkeypatch, tmp_path)
    db = session_local()
    try:
        scan = create_scan(
            db,
            scan_id="scan_002",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="queued",
        )
        create_task(db, task_id="task_semgrep", scan_id=scan.id, task_type="scanner", tool_name="semgrep", status="queued")
        create_task(db, task_id="task_gitleaks", scan_id=scan.id, task_type="scanner", tool_name="gitleaks", status="queued")
        create_task(db, task_id="task_trivy", scan_id=scan.id, task_type="scanner", tool_name="trivy", status="queued")
    finally:
        db.close()

    semgrep_json = (Path(__file__).parent / "fixtures" / "sample_semgrep.json").read_text(encoding="utf-8")
    trivy_json = (Path(__file__).parent / "fixtures" / "sample_trivy.json").read_text(encoding="utf-8")

    monkeypatch.setattr(hermes, "run_semgrep", lambda target_path, output_path, timeout=None: CommandResult(stdout=semgrep_json, stderr="", exit_code=0))
    monkeypatch.setattr(hermes, "run_gitleaks", lambda target_path, output_path, timeout=None: CommandResult(stdout="", stderr="gitleaks failed", exit_code=1, error_message="gitleaks failed"))
    monkeypatch.setattr(hermes, "run_trivy_fs", lambda target_path, output_path, timeout=None: CommandResult(stdout=trivy_json, stderr="", exit_code=0))

    hermes.run_scan("scan_002")

    db = session_local()
    try:
        scan = get_scan(db, "scan_002")
        tasks = list_tasks_by_scan(db, "scan_002")
        findings = list_findings_by_scan(db, "scan_002")
    finally:
        db.close()

    assert scan is not None
    assert scan.status == "failed"
    status_by_tool = {task.tool_name: task.status for task in tasks}
    error_by_tool = {task.tool_name: task.error_message for task in tasks}
    assert status_by_tool == {"semgrep": "completed", "gitleaks": "failed", "trivy": "completed"}
    assert error_by_tool["gitleaks"] == "gitleaks failed"
    assert Counter(finding.scanner for finding in findings) == Counter({"semgrep": 4, "trivy": 2})
