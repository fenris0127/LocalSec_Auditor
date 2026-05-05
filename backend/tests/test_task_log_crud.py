from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.scan import create_scan
from app.crud.task import create_task
from app.crud.task_log import create_task_log, list_task_logs
from app.db.base import Base
from app.models.task_log import TaskLog


def make_session(tmp_path):
    db_path = tmp_path / "task_logs.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def test_create_and_list_task_logs(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan(
            db,
            scan_id="scan_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="queued",
            created_at=datetime(2026, 5, 5, 10, 0, 0),
        )
        create_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="semgrep",
            status="queued",
        )

        first = create_task_log(
            db,
            log_id="log_001",
            task_id="task_001",
            level="info",
            message="Task started",
            created_at=datetime(2026, 5, 5, 10, 1, 0),
        )
        create_task_log(
            db,
            log_id="log_002",
            task_id="task_001",
            level="error",
            message="Task failed",
            created_at=datetime(2026, 5, 5, 10, 2, 0),
        )

        logs = list_task_logs(db, "task_001")

        assert isinstance(first, TaskLog)
        assert [log.id for log in logs] == ["log_001", "log_002"]
        assert [log.level for log in logs] == ["info", "error"]
        assert [log.message for log in logs] == ["Task started", "Task failed"]
    finally:
        db.close()


def test_create_task_log_masks_secret_like_values(tmp_path):
    secret_value = "sk_test_task_log_secret_value"
    db = make_session(tmp_path)
    try:
        create_scan(
            db,
            scan_id="scan_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="queued",
        )
        create_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="gitleaks",
            status="queued",
        )

        log = create_task_log(
            db,
            log_id="log_001",
            task_id="task_001",
            level="warning",
            message=f"scanner stderr contained {secret_value}",
        )

        assert secret_value not in log.message
        assert "[REDACTED_SECRET]" in log.message
    finally:
        db.close()
