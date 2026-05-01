from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.task import ScanTask


def create_task(
    db: Session,
    *,
    task_id: str,
    scan_id: str,
    task_type: str,
    status: str,
    tool_name: str | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    error_message: str | None = None,
) -> ScanTask:
    task = ScanTask(
        id=task_id,
        scan_id=scan_id,
        task_type=task_type,
        tool_name=tool_name,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        error_message=error_message,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def update_task_status(
    db: Session,
    *,
    task_id: str,
    status: str,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    error_message: str | None = None,
) -> ScanTask | None:
    task = db.get(ScanTask, task_id)
    if task is None:
        return None

    task.status = status
    if started_at is not None:
        task.started_at = started_at
    if finished_at is not None:
        task.finished_at = finished_at
    task.error_message = error_message
    db.commit()
    db.refresh(task)
    return task


def list_tasks_by_scan(db: Session, scan_id: str) -> list[ScanTask]:
    statement = select(ScanTask).where(ScanTask.scan_id == scan_id).order_by(ScanTask.id)
    return list(db.scalars(statement))
