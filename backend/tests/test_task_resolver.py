from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.scan import create_scan
from app.crud.workflow_task import create_workflow_task, get_workflow_task
from app.db.base import Base
from app.orchestrator.task_resolver import TaskGraphCycleError, get_ready_tasks


def make_session(tmp_path):
    db_path = tmp_path / "task_resolver.db"
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


def test_dependency_free_pending_task_is_ready(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="semgrep",
            status="pending",
        )

        ready_tasks = get_ready_tasks("scan_001", db=db)
        saved = get_workflow_task(db, "task_001")

        assert [task.id for task in ready_tasks] == ["task_001"]
        assert saved is not None
        assert saved.status == "ready"
    finally:
        db.close()


def test_dependent_task_is_ready_after_dependencies_completed(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="syft",
            status="completed",
        )
        create_workflow_task(
            db,
            task_id="task_002",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="grype",
            status="pending",
            depends_on=["task_001"],
        )

        ready_tasks = get_ready_tasks("scan_001", db=db)
        saved = get_workflow_task(db, "task_002")

        assert [task.id for task in ready_tasks] == ["task_002"]
        assert saved is not None
        assert saved.status == "ready"
    finally:
        db.close()


def test_dependent_task_is_not_ready_when_dependency_pending(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="syft",
            status="pending",
        )
        create_workflow_task(
            db,
            task_id="task_002",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="grype",
            status="pending",
            depends_on=["task_001"],
        )

        ready_tasks = get_ready_tasks("scan_001", db=db)

        assert [task.id for task in ready_tasks] == ["task_001"]
        assert get_workflow_task(db, "task_002").status == "pending"
    finally:
        db.close()


def test_dependent_task_is_skipped_when_dependency_failed(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="syft",
            status="failed",
            error_message="scanner failed",
        )
        create_workflow_task(
            db,
            task_id="task_002",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="grype",
            status="pending",
            depends_on=["task_001"],
        )

        ready_tasks = get_ready_tasks("scan_001", db=db)
        saved = get_workflow_task(db, "task_002")

        assert ready_tasks == []
        assert saved is not None
        assert saved.status == "skipped"
        assert saved.error_message == "dependency failed or was not executed"
    finally:
        db.close()


def test_cycle_detection_raises_clear_error(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan_record(db)
        create_workflow_task(
            db,
            task_id="task_001",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="syft",
            status="pending",
            depends_on=["task_002"],
        )
        create_workflow_task(
            db,
            task_id="task_002",
            scan_id="scan_001",
            task_type="scanner",
            tool_name="grype",
            status="pending",
            depends_on=["task_001"],
        )

        with pytest.raises(TaskGraphCycleError, match="dependency cycle detected"):
            get_ready_tasks("scan_001", db=db)
    finally:
        db.close()
