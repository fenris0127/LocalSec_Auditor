from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.scan import create_scan
from app.crud.workflow_task import create_workflow_task, get_workflow_task
from app.db.base import Base
from app.orchestrator.task_retry import record_task_failure


def make_session(tmp_path):
    db_path = tmp_path / "task_retry.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def create_scan_record(db):
    return create_scan(
        db,
        scan_id="scan_001",
        project_name="demo",
        target_path="C:/AI/projects/demo",
        status="created",
        created_at=datetime(2026, 5, 5, 10, 0, 0),
    )


def test_scanner_task_failure_retries_before_max_retries(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="semgrep",
            status="running",
            retry_count=0,
            max_retries=2,
        )

        updated = record_task_failure("task_001", "temporary scanner failure", db=db)

        assert updated is not None
        assert updated.retry_count == 1
        assert updated.status == "pending"
        assert updated.error_message == "temporary scanner failure"
    finally:
        db.close()


def test_scanner_task_failure_becomes_failed_at_max_retries(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="semgrep",
            status="running",
            retry_count=1,
            max_retries=2,
        )

        updated = record_task_failure("task_001", "final scanner failure", db=db)

        assert updated is not None
        assert updated.retry_count == 2
        assert updated.status == "failed"
        assert updated.error_message == "final scanner failure"
    finally:
        db.close()


def test_failed_task_at_retry_limit_remains_fixed(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="semgrep",
            status="failed",
            retry_count=2,
            max_retries=2,
            error_message="already final",
        )

        updated = record_task_failure("task_001", "ignored", db=db)

        assert updated is not None
        assert updated.retry_count == 2
        assert updated.status == "failed"
        assert updated.error_message == "already final"
    finally:
        db.close()


def test_non_scanner_task_failure_does_not_retry(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="analysis",
            tool_name=None,
            status="running",
            retry_count=0,
            max_retries=3,
        )

        updated = record_task_failure("task_001", "analysis failed", db=db)

        assert updated is not None
        assert updated.retry_count == 1
        assert updated.status == "failed"
        assert updated.error_message == "analysis failed"
    finally:
        db.close()


def test_record_task_failure_returns_none_for_missing_task(tmp_path):
    db = make_session(tmp_path)
    try:
        assert record_task_failure("missing", "unused", db=db) is None
    finally:
        db.close()
