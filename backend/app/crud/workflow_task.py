import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.workflow_task import WorkflowTask


WORKFLOW_TASK_STATUSES = {
    "pending",
    "ready",
    "running",
    "completed",
    "failed",
    "skipped",
    "cancelled",
}


def _depends_on_to_json(depends_on: list[str] | None) -> str:
    unique_dependencies = []
    for task_id in depends_on or []:
        if task_id and task_id not in unique_dependencies:
            unique_dependencies.append(task_id)
    return json.dumps(unique_dependencies)


def depends_on_from_json(value: str | None) -> list[str]:
    if not value:
        return []
    payload = json.loads(value)
    if not isinstance(payload, list):
        return []
    return [str(task_id) for task_id in payload]


def _validate_workflow_status(status: str) -> None:
    if status not in WORKFLOW_TASK_STATUSES:
        allowed = ", ".join(sorted(WORKFLOW_TASK_STATUSES))
        raise ValueError(f"unsupported workflow task status: {status}; allowed: {allowed}")


def create_workflow_task(
    db: Session,
    *,
    task_id: str,
    scan_id: str,
    task_type: str,
    status: str,
    tool_name: str | None = None,
    depends_on: list[str] | None = None,
    retry_count: int = 0,
    max_retries: int = 0,
    error_message: str | None = None,
) -> WorkflowTask:
    _validate_workflow_status(status)
    task = WorkflowTask(
        id=task_id,
        scan_id=scan_id,
        task_type=task_type,
        tool_name=tool_name,
        status=status,
        depends_on=_depends_on_to_json(depends_on),
        retry_count=retry_count,
        max_retries=max_retries,
        error_message=error_message,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def get_workflow_task(db: Session, task_id: str) -> WorkflowTask | None:
    return db.get(WorkflowTask, task_id)


def list_workflow_tasks_by_scan(db: Session, scan_id: str) -> list[WorkflowTask]:
    statement = select(WorkflowTask).where(WorkflowTask.scan_id == scan_id).order_by(WorkflowTask.id)
    return list(db.scalars(statement))


def get_workflow_task_dependencies(db: Session, task_id: str) -> list[str] | None:
    task = db.get(WorkflowTask, task_id)
    if task is None:
        return None
    return depends_on_from_json(task.depends_on)


def update_workflow_task_status(
    db: Session,
    *,
    task_id: str,
    status: str,
    retry_count: int | None = None,
    error_message: str | None = None,
) -> WorkflowTask | None:
    _validate_workflow_status(status)
    task = db.get(WorkflowTask, task_id)
    if task is None:
        return None

    task.status = status
    if retry_count is not None:
        task.retry_count = retry_count
    task.error_message = error_message
    db.commit()
    db.refresh(task)
    return task
