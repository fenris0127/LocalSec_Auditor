from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.crud.finding import list_findings_by_scan
from app.crud.scan import create_scan, get_scan, list_scans
from app.crud.task import create_task, list_tasks_by_scan
from app.core.workspace import get_workspace_root, is_path_inside_workspace
from app.db.database import get_db_session
from app.orchestrator.hermes import run_scan
from app.reports import generate_markdown_report, get_markdown_report_path
from app.schemas.scan import (
    ScanCreateRequest,
    ScanCreateResponse,
    ScanResponse,
    ScanTaskResponse,
)
from app.schemas.finding import FindingResponse


router = APIRouter(prefix="/api/scans", tags=["scans"])
TASK_CREATION_ORDER = ["syft", "grype", "trivy", "semgrep", "gitleaks", "lynis", "openscap"]


def _ordered_scan_types(scan_types: list[str]) -> list[str]:
    requested = set(scan_types)
    if "grype" in requested:
        requested.add("syft")
    return [scan_type for scan_type in TASK_CREATION_ORDER if scan_type in requested]


@router.post("", response_model=ScanCreateResponse)
def create_scan_api(
    request: ScanCreateRequest,
    db: Session = Depends(get_db_session),
) -> ScanCreateResponse:
    if not is_path_inside_workspace(request.target_path):
        raise HTTPException(
            status_code=400,
            detail=f"target_path must be inside workspace: {get_workspace_root()}",
        )

    scan_id = f"scan_{uuid4().hex}"
    status = "queued"

    scan = create_scan(
        db,
        scan_id=scan_id,
        project_name=request.project_name,
        target_path=request.target_path,
        status=status,
    )

    for scan_type in _ordered_scan_types(request.scan_types):
        create_task(
            db,
            task_id=f"task_{uuid4().hex}",
            scan_id=scan.id,
            task_type="scanner",
            tool_name=scan_type,
            status=status,
        )

    if request.run_immediately:
        # TODO: Move scan execution to a background worker when the MVP needs async processing.
        run_scan(scan.id)
        db.refresh(scan)

    return ScanCreateResponse(scan_id=scan.id, status=scan.status)


@router.get("", response_model=list[ScanResponse])
def list_scans_api(db: Session = Depends(get_db_session)) -> list[ScanResponse]:
    return list_scans(db)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_api(
    scan_id: str,
    db: Session = Depends(get_db_session),
) -> ScanResponse:
    scan = get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/tasks", response_model=list[ScanTaskResponse])
def list_scan_tasks_api(
    scan_id: str,
    db: Session = Depends(get_db_session),
) -> list[ScanTaskResponse]:
    scan = get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return list_tasks_by_scan(db, scan_id)


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def list_scan_findings_api(
    scan_id: str,
    db: Session = Depends(get_db_session),
) -> list[FindingResponse]:
    scan = get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return list_findings_by_scan(db, scan_id)


@router.post("/{scan_id}/report")
def create_scan_report_api(
    scan_id: str,
    db: Session = Depends(get_db_session),
) -> dict[str, str]:
    scan = get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        report_path = generate_markdown_report(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc

    return {
        "report_path": str(report_path),
        "content": report_path.read_text(encoding="utf-8"),
    }


@router.get("/{scan_id}/report")
def get_scan_report_api(
    scan_id: str,
    db: Session = Depends(get_db_session),
) -> dict[str, str]:
    scan = get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_path = get_markdown_report_path(scan_id)
    if not report_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "report_path": str(report_path),
        "content": report_path.read_text(encoding="utf-8"),
    }
