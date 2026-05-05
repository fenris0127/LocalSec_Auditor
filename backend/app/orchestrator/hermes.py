from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.crud.finding import create_finding, mark_findings_superseded_by_scanner
from app.crud.scan import get_scan, update_scan_status
from app.crud.task import get_task, list_tasks_by_scan, update_task_status
from app.crud.task_log import create_task_log
from app.db.database import SessionLocal
from app.llm.secret_masking import mask_secret_text
from app.normalizers.gitleaks import normalize_gitleaks
from app.normalizers.grype import normalize_grype
from app.normalizers.semgrep import normalize_semgrep
from app.normalizers.trivy import normalize_trivy
from app.scanners.gitleaks import run_gitleaks
from app.scanners.grype import run_grype_sbom
from app.scanners.semgrep import run_semgrep
from app.scanners.syft import run_syft
from app.scanners.trivy import run_trivy_fs
from app.services.scan_dirs import create_scan_dirs


TASK_TOOL_ORDER = {"syft": 0, "grype": 1, "trivy": 2, "semgrep": 3, "gitleaks": 4}


@dataclass(frozen=True)
class TaskRerunResult:
    scan_id: str
    task_id: str
    task_status: str
    superseded_findings: int
    new_findings: int


def _sorted_tasks(tasks):
    return sorted(
        tasks,
        key=lambda task: (TASK_TOOL_ORDER.get(task.tool_name or "", 99), task.id),
    )


def _scanner_for_tool(tool_name: str):
    if tool_name == "semgrep":
        return run_semgrep, normalize_semgrep, "semgrep.json"
    if tool_name == "gitleaks":
        return run_gitleaks, normalize_gitleaks, "gitleaks.json"
    if tool_name == "trivy":
        return run_trivy_fs, normalize_trivy, "trivy.json"
    raise ValueError(f"Unsupported scan tool: {tool_name}")


def _raw_path_for_tool(tool_name: str, paths: dict[str, Path]) -> Path:
    if tool_name == "syft":
        return paths["raw_syft_sbom"]
    if tool_name == "grype":
        return paths["raw_grype"]
    return paths["raw"] / f"{tool_name}.json"


def _run_tool(tool_name: str, target_path: str, raw_path: Path, paths: dict[str, Path]):
    if tool_name == "syft":
        return run_syft(target_path, str(raw_path)), None
    if tool_name == "grype":
        return run_grype_sbom(str(paths["raw_syft_sbom"]), str(raw_path)), normalize_grype

    runner, normalizer, _ = _scanner_for_tool(tool_name)
    return runner(target_path, str(raw_path)), normalizer


def _persist_raw_output(raw_path: Path, result, *, overwrite: bool = False) -> None:
    if raw_path.exists() and not overwrite:
        return
    if result.stdout:
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(result.stdout, encoding="utf-8")


def _persist_findings(db, findings) -> int:
    created = 0
    for finding in findings:
        create_finding(
            db,
            finding_id=finding.id,
            scan_id=finding.scan_id,
            category=finding.category,
            scanner=finding.scanner,
            severity=finding.severity,
            title=finding.title,
            rule_id=finding.rule_id,
            status=finding.status,
            file_path=finding.file_path,
            line=finding.line,
            component=finding.component,
            installed_version=finding.installed_version,
            fixed_version=finding.fixed_version,
            cve=finding.cve,
            cwe=finding.cwe,
            cce_id=finding.cce_id,
            current_value=finding.current_value,
            expected_value=finding.expected_value,
            raw_json_path=finding.raw_json_path,
            llm_summary=finding.llm_summary,
        )
        created += 1
    return created


def _run_single_task(db, scan, task, *, overwrite_raw: bool = False) -> tuple[str, int]:
    tool_name = task.tool_name or ""
    paths = create_scan_dirs(scan.id)
    raw_path = _raw_path_for_tool(tool_name, paths)

    create_task_log(db, task_id=task.id, level="info", message=f"Starting task for {tool_name or 'unknown'}")
    update_task_status(
        db,
        task_id=task.id,
        status="running",
        started_at=datetime.utcnow(),
        error_message=None,
    )

    try:
        result, normalizer = _run_tool(tool_name, scan.target_path, raw_path, paths)
        if result.stderr:
            create_task_log(db, task_id=task.id, level="warning", message=result.stderr)

        if result.exit_code != 0:
            error_message = mask_secret_text(
                result.error_message
                or result.stderr
                or f"{tool_name} failed with exit code {result.exit_code}"
            )
            create_task_log(db, task_id=task.id, level="error", message=error_message)
            update_task_status(
                db,
                task_id=task.id,
                status="failed",
                finished_at=datetime.utcnow(),
                error_message=error_message,
            )
            return "failed", 0

        _persist_raw_output(raw_path, result, overwrite=overwrite_raw)
        new_findings = 0
        if normalizer is not None:
            findings = normalizer(str(raw_path), scan.id)
            new_findings = _persist_findings(db, findings)

        create_task_log(db, task_id=task.id, level="info", message=f"Completed task for {tool_name or 'unknown'}")
        update_task_status(
            db,
            task_id=task.id,
            status="completed",
            finished_at=datetime.utcnow(),
            error_message=None,
        )
        return "completed", new_findings
    except Exception as exc:
        error_message = mask_secret_text(exc)
        create_task_log(db, task_id=task.id, level="error", message=error_message)
        update_task_status(
            db,
            task_id=task.id,
            status="failed",
            finished_at=datetime.utcnow(),
            error_message=error_message,
        )
        return "failed", 0


def run_scan(scan_id: str) -> None:
    db = SessionLocal()
    try:
        scan = get_scan(db, scan_id)
        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")
        if scan.status == "cancelled":
            return

        started_at = datetime.utcnow()
        update_scan_status(db, scan_id=scan_id, status="running", started_at=started_at)

        tasks = _sorted_tasks(list_tasks_by_scan(db, scan_id))
        overall_failed = False

        for task in tasks:
            task_status, _ = _run_single_task(db, scan, task)
            if task_status == "failed":
                overall_failed = True

        update_scan_status(
            db,
            scan_id=scan_id,
            status="failed" if overall_failed else "completed",
            finished_at=datetime.utcnow(),
        )
    finally:
        db.close()


def rerun_scan_task(scan_id: str, task_id: str, db=None) -> TaskRerunResult:
    owns_session = db is None
    if db is None:
        db = SessionLocal()

    try:
        scan = get_scan(db, scan_id)
        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")

        task = get_task(db, task_id)
        if task is None or task.scan_id != scan_id:
            raise ValueError(f"Task not found: {task_id}")

        tool_name = task.tool_name or ""
        update_task_status(db, task_id=task.id, status="pending", error_message=None)
        superseded_findings = mark_findings_superseded_by_scanner(
            db,
            scan_id=scan_id,
            scanner=tool_name,
        )

        task_status, new_findings = _run_single_task(db, scan, task, overwrite_raw=True)
        return TaskRerunResult(
            scan_id=scan_id,
            task_id=task_id,
            task_status=task_status,
            superseded_findings=superseded_findings,
            new_findings=new_findings,
        )
    finally:
        if owns_session:
            db.close()
