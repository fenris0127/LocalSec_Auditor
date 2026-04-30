from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.scan import create_scan
from app.crud.task import create_task, list_tasks_by_scan, update_task_status
from app.db.base import Base
from app.models.scan import Scan
from app.models.task import ScanTask


def make_session(tmp_path):
    db_path = tmp_path / "tasks.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def test_create_multiple_tasks_for_scan(tmp_path):
    db = make_session(tmp_path)
    try:
        scan = create_scan(
            db,
            scan_id="scan_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="created",
            created_at=datetime(2026, 4, 30, 10, 0, 0),
        )
        first = create_task(
            db,
            task_id="task_001",
            scan_id=scan.id,
            task_type="scanner",
            tool_name="semgrep",
            status="pending",
        )
        second = create_task(
            db,
            task_id="task_002",
            scan_id=scan.id,
            task_type="scanner",
            tool_name=None,
            status="pending",
        )

        tasks = list_tasks_by_scan(db, "scan_001")

        assert isinstance(scan, Scan)
        assert isinstance(first, ScanTask)
        assert isinstance(second, ScanTask)
        assert [task.id for task in tasks] == ["task_001", "task_002"]
        assert tasks[0].tool_name == "semgrep"
        assert tasks[1].tool_name is None
    finally:
        db.close()


def test_update_task_status(tmp_path):
    db = make_session(tmp_path)
    started_at = datetime(2026, 4, 30, 10, 1, 0)
    finished_at = datetime(2026, 4, 30, 10, 2, 0)
    try:
        create_scan(
            db,
            scan_id="scan_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="created",
        )
        create_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="semgrep",
            status="pending",
        )

        updated = update_task_status(
            db,
            task_id="task_001",
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
        )

        assert updated is not None
        assert updated.status == "completed"
        assert updated.started_at == started_at
        assert updated.finished_at == finished_at
        assert updated.error_message is None
    finally:
        db.close()


def test_update_missing_task_returns_none(tmp_path):
    db = make_session(tmp_path)
    try:
        assert update_task_status(db, task_id="missing", status="failed") is None
    finally:
        db.close()
