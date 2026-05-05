from __future__ import annotations

from sqlalchemy.orm import Session

from app.crud.workflow_task import (
    depends_on_from_json,
    list_workflow_tasks_by_scan,
    update_workflow_task_status,
)
from app.db.database import SessionLocal
from app.models.workflow_task import WorkflowTask


class TaskGraphCycleError(ValueError):
    pass


TERMINAL_BLOCKING_STATUSES = {"failed", "skipped", "cancelled"}


def _dependency_ids(task: WorkflowTask) -> list[str]:
    return depends_on_from_json(task.depends_on)


def _detect_cycle(tasks: list[WorkflowTask]) -> None:
    task_by_id = {task.id: task for task in tasks}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str, path: list[str]) -> None:
        if task_id in visiting:
            cycle_start = path.index(task_id) if task_id in path else 0
            cycle = [*path[cycle_start:], task_id]
            raise TaskGraphCycleError(f"workflow task dependency cycle detected: {' -> '.join(cycle)}")
        if task_id in visited:
            return

        task = task_by_id.get(task_id)
        if task is None:
            return

        visiting.add(task_id)
        for dependency_id in _dependency_ids(task):
            if dependency_id in task_by_id:
                visit(dependency_id, [*path, dependency_id])
        visiting.remove(task_id)
        visited.add(task_id)

    for task in tasks:
        visit(task.id, [task.id])


def _get_ready_tasks(db: Session, *, scan_id: str) -> list[WorkflowTask]:
    tasks = list_workflow_tasks_by_scan(db, scan_id)
    _detect_cycle(tasks)

    task_by_id = {task.id: task for task in tasks}
    ready_tasks: list[WorkflowTask] = []

    for task in tasks:
        if task.status not in {"pending", "ready"}:
            continue

        dependencies = [
            task_by_id[dependency_id]
            for dependency_id in _dependency_ids(task)
            if dependency_id in task_by_id
        ]
        if any(dependency.status in TERMINAL_BLOCKING_STATUSES for dependency in dependencies):
            skipped = update_workflow_task_status(
                db,
                task_id=task.id,
                status="skipped",
                error_message="dependency failed or was not executed",
            )
            if skipped is not None:
                task_by_id[task.id] = skipped
            continue

        if all(dependency.status == "completed" for dependency in dependencies):
            ready = (
                update_workflow_task_status(db, task_id=task.id, status="ready", error_message=None)
                if task.status != "ready"
                else task
            )
            if ready is not None:
                task_by_id[task.id] = ready
                ready_tasks.append(ready)

    return ready_tasks


def get_ready_tasks(scan_id: str, db: Session | None = None) -> list[WorkflowTask]:
    if db is not None:
        return _get_ready_tasks(db, scan_id=scan_id)

    local_db = SessionLocal()
    try:
        return _get_ready_tasks(local_db, scan_id=scan_id)
    finally:
        local_db.close()
