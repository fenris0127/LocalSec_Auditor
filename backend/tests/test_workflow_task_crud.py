from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.scan import create_scan
from app.crud.workflow_task import (
    create_workflow_task,
    get_workflow_task,
    get_workflow_task_dependencies,
    list_workflow_tasks_by_scan,
    update_workflow_task_status,
)
from app.db.base import Base
from app.models.workflow_task import WorkflowTask


def make_session(tmp_path):
    db_path = tmp_path / "workflow_tasks.db"
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


def test_create_workflow_task_graph_with_dependencies(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        first = create_workflow_task(
            db,
            task_id="workflow_task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="syft",
            status="ready",
        )
        second = create_workflow_task(
            db,
            task_id="workflow_task_002",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="grype",
            status="pending",
            depends_on=["workflow_task_001"],
            max_retries=2,
        )
        third = create_workflow_task(
            db,
            task_id="workflow_task_003",
            scan_id="scan_001",
            task_type="analysis",
            tool_name=None,
            status="pending",
            depends_on=["workflow_task_001", "workflow_task_002"],
        )

        tasks = list_workflow_tasks_by_scan(db, "scan_001")

        assert isinstance(first, WorkflowTask)
        assert second.max_retries == 2
        assert [task.id for task in tasks] == [
            "workflow_task_001",
            "workflow_task_002",
            "workflow_task_003",
        ]
        assert get_workflow_task_dependencies(db, "workflow_task_001") == []
        assert get_workflow_task_dependencies(db, "workflow_task_002") == ["workflow_task_001"]
        assert get_workflow_task_dependencies(db, "workflow_task_003") == [
            "workflow_task_001",
            "workflow_task_002",
        ]
    finally:
        db.close()


def test_get_workflow_task_returns_saved_retry_and_error_fields(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="workflow_task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="semgrep",
            status="failed",
            retry_count=1,
            max_retries=3,
            error_message="scanner failed",
        )

        task = get_workflow_task(db, "workflow_task_001")

        assert task is not None
        assert task.retry_count == 1
        assert task.max_retries == 3
        assert task.error_message == "scanner failed"
    finally:
        db.close()


def test_update_workflow_task_status_updates_retry_and_error(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="workflow_task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="semgrep",
            status="running",
            max_retries=2,
        )

        updated = update_workflow_task_status(
            db,
            task_id="workflow_task_001",
            status="failed",
            retry_count=1,
            error_message="timeout",
        )

        assert updated is not None
        assert updated.status == "failed"
        assert updated.retry_count == 1
        assert updated.error_message == "timeout"
    finally:
        db.close()


def test_workflow_task_rejects_unsupported_status(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)

        with pytest.raises(ValueError, match="unsupported workflow task status"):
            create_workflow_task(
                db,
                task_id="workflow_task_001",
                scan_id="scan_001",
                task_type="scanner",
                status="queued",
            )
    finally:
        db.close()
