from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.project import create_project
from app.crud.scan import create_scan, get_scan, list_scans
from app.db.base import Base
from app.models.scan import Scan


def make_session(tmp_path):
    db_path = tmp_path / "scans.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def test_create_scan_then_get_scan(tmp_path):
    db = make_session(tmp_path)
    created_at = datetime(2026, 4, 30, 10, 0, 0)
    try:
        created = create_scan(
            db,
            scan_id="scan_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="created",
            created_at=created_at,
        )

        found = get_scan(db, "scan_001")

        assert isinstance(created, Scan)
        assert found is not None
        assert found.id == "scan_001"
        assert found.project_name == "demo"
        assert found.target_path == "C:/AI/projects/demo"
        assert found.status == "created"
        assert found.started_at is None
        assert found.finished_at is None
        assert found.created_at == created_at
    finally:
        db.close()


def test_list_scans_returns_created_scans(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan(
            db,
            scan_id="scan_old",
            project_name="old",
            target_path="C:/AI/projects/old",
            status="created",
            created_at=datetime(2026, 4, 30, 9, 0, 0),
        )
        create_scan(
            db,
            scan_id="scan_new",
            project_name="new",
            target_path="C:/AI/projects/new",
            status="created",
            created_at=datetime(2026, 4, 30, 10, 0, 0),
        )

        scans = list_scans(db)

        assert [scan.id for scan in scans] == ["scan_new", "scan_old"]
    finally:
        db.close()


def test_create_scan_can_link_project_id(tmp_path):
    db = make_session(tmp_path)
    try:
        create_project(
            db,
            project_id="project_001",
            name="demo",
            root_path="C:/AI/projects/demo",
            created_at=datetime(2026, 4, 30, 9, 0, 0),
        )

        created = create_scan(
            db,
            scan_id="scan_001",
            project_id="project_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="created",
            created_at=datetime(2026, 4, 30, 10, 0, 0),
        )
        found = get_scan(db, "scan_001")

        assert created.project_id == "project_001"
        assert found is not None
        assert found.project_id == "project_001"
        assert found.project_name == "demo"
    finally:
        db.close()
