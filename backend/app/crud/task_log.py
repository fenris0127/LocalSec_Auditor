from datetime import datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.llm.secret_masking import mask_secret_text
from app.models.task_log import TaskLog


def create_task_log(
    db: Session,
    *,
    task_id: str,
    level: str,
    message: object,
    log_id: str | None = None,
    created_at: datetime | None = None,
) -> TaskLog:
    log = TaskLog(
        id=log_id or f"task_log_{uuid4().hex}",
        task_id=task_id,
        level=level,
        message=mask_secret_text(message),
        created_at=created_at or datetime.utcnow(),
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def list_task_logs(db: Session, task_id: str) -> list[TaskLog]:
    statement = select(TaskLog).where(TaskLog.task_id == task_id).order_by(TaskLog.created_at, TaskLog.id)
    return list(db.scalars(statement))
