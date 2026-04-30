from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.crud.scan import create_scan, get_scan, list_scans
from app.crud.task import create_task, list_tasks_by_scan
from app.db.database import get_db_session
from app.schemas.scan import (
    ScanCreateRequest,
    ScanCreateResponse,
    ScanResponse,
    ScanTaskResponse,
)


router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanCreateResponse)
def create_scan_api(
    request: ScanCreateRequest,
    db: Session = Depends(get_db_session),
) -> ScanCreateResponse:
    scan_id = f"scan_{uuid4().hex}"
    status = "queued"

    scan = create_scan(
        db,
        scan_id=scan_id,
        project_name=request.project_name,
        target_path=request.target_path,
        status=status,
    )

    for scan_type in request.scan_types:
        create_task(
            db,
            task_id=f"task_{uuid4().hex}",
            scan_id=scan.id,
            task_type="scanner",
            tool_name=scan_type,
            status=status,
        )

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
