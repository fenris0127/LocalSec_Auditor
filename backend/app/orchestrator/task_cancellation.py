from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.crud.scan import get_scan, update_scan_status
from app.crud.task import list_tasks_by_scan, update_task_status
from app.db.database import SessionLocal


CANCELLABLE_TASK_STATUSES = {"pending", "ready", "queued"}


@dataclass(frozen=True)
class ScanCancellationResult:
    scan_id: str
    scan_status: str
    cancelled_tasks: int
    running_tasks: int


def cancel_scan(scan_id: str, db: Session | None = None) -> ScanCancellationResult:
    owns_session = db is None
    if db is None:
        db = SessionLocal()

    try:
        scan = get_scan(db, scan_id)
        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")

        tasks = list_tasks_by_scan(db, scan_id)
        cancelled_tasks = 0
        running_tasks = 0

        for task in tasks:
            if task.status == "running":
                running_tasks += 1
                continue
            if task.status in CANCELLABLE_TASK_STATUSES:
                update_task_status(
                    db,
                    task_id=task.id,
                    status="cancelled",
                    error_message=None,
                )
                cancelled_tasks += 1

        scan_status = "cancelling" if running_tasks else "cancelled"
        update_scan_status(db, scan_id=scan_id, status=scan_status)

        return ScanCancellationResult(
            scan_id=scan_id,
            scan_status=scan_status,
            cancelled_tasks=cancelled_tasks,
            running_tasks=running_tasks,
        )
    finally:
        if owns_session:
            db.close()
