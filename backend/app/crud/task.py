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


def get_scan_task_progress(db: Session, scan_id: str) -> dict[str, object]:
    tasks = list_tasks_by_scan(db, scan_id)
    total_tasks = len(tasks)

    completed_tasks = sum(1 for task in tasks if task.status == "completed")
    failed_tasks = sum(1 for task in tasks if task.status == "failed")
    running_tasks = sum(1 for task in tasks if task.status == "running")
    pending_tasks = sum(1 for task in tasks if task.status in {"pending", "queued", "ready"})
    cancelled_tasks = sum(1 for task in tasks if task.status == "cancelled")
    finished_tasks = completed_tasks + failed_tasks + cancelled_tasks
    progress_percent = round((finished_tasks / total_tasks) * 100, 2) if total_tasks else 0.0

    running_task = next((task for task in tasks if task.status == "running"), None)
    current_task = None
    if running_task is not None:
        current_task = {
            "id": running_task.id,
            "task_type": running_task.task_type,
            "tool_name": running_task.tool_name,
            "status": running_task.status,
        }

    return {
        "total_tasks": total_tasks,
        "completed_tasks": completed_tasks,
        "failed_tasks": failed_tasks,
        "running_tasks": running_tasks,
        "pending_tasks": pending_tasks,
        "cancelled_tasks": cancelled_tasks,
        "progress_percent": progress_percent,
        "current_task": current_task,
    }
