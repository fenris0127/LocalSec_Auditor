from __future__ import annotations

from sqlalchemy.orm import Session

from app.crud.workflow_task import get_workflow_task, update_workflow_task_status
from app.db.database import SessionLocal
from app.models.workflow_task import WorkflowTask


def _record_task_failure(
    db: Session,
    *,
    task_id: str,
    error_message: str | None = None,
) -> WorkflowTask | None:
    task = get_workflow_task(db, task_id)
    if task is None:
        return None

    if task.status == "failed" and task.retry_count >= task.max_retries:
        return task

    retry_count = task.retry_count + 1
    should_retry = task.task_type == "scanner" and retry_count < task.max_retries
    next_status = "pending" if should_retry else "failed"

    return update_workflow_task_status(
        db,
        task_id=task.id,
        status=next_status,
        retry_count=retry_count,
        error_message=error_message,
    )


def record_task_failure(
    task_id: str,
    error_message: str | None = None,
    db: Session | None = None,
) -> WorkflowTask | None:
    if db is not None:
        return _record_task_failure(db, task_id=task_id, error_message=error_message)

    local_db = SessionLocal()
    try:
        return _record_task_failure(local_db, task_id=task_id, error_message=error_message)
    finally:
        local_db.close()
