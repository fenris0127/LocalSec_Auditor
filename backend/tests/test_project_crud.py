from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.project import create_project, get_project, list_projects, update_project
from app.db.base import Base
from app.models.project import Project


def make_session(tmp_path):
    db_path = tmp_path / "projects.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def test_create_project_then_get_project(tmp_path):
    db = make_session(tmp_path)
    created_at = datetime(2026, 5, 2, 10, 0, 0)
    try:
        created = create_project(
            db,
            project_id="project_001",
            name="demo",
            root_path="C:/AI/projects/demo",
            created_at=created_at,
            updated_at=created_at,
        )

        found = get_project(db, "project_001")

        assert isinstance(created, Project)
        assert found is not None
        assert found.id == "project_001"
        assert found.name == "demo"
        assert found.root_path == "C:/AI/projects/demo"
        assert found.created_at == created_at
        assert found.updated_at == created_at
    finally:
        db.close()


def test_list_projects_returns_created_projects(tmp_path):
    db = make_session(tmp_path)
    try:
        create_project(
            db,
            project_id="project_old",
            name="old",
            root_path="C:/AI/projects/old",
            created_at=datetime(2026, 5, 2, 9, 0, 0),
        )
        create_project(
            db,
            project_id="project_new",
            name="new",
            root_path="C:/AI/projects/new",
            created_at=datetime(2026, 5, 2, 10, 0, 0),
        )

        projects = list_projects(db)

        assert [project.id for project in projects] == ["project_new", "project_old"]
    finally:
        db.close()


def test_update_project_changes_mutable_fields(tmp_path):
    db = make_session(tmp_path)
    updated_at = datetime(2026, 5, 2, 11, 0, 0)
    try:
        create_project(
            db,
            project_id="project_001",
            name="demo",
            root_path="C:/AI/projects/demo",
            created_at=datetime(2026, 5, 2, 10, 0, 0),
        )

        updated = update_project(
            db,
            project_id="project_001",
            name="demo-renamed",
            root_path="C:/AI/projects/demo-renamed",
            updated_at=updated_at,
        )

        assert updated is not None
        assert updated.name == "demo-renamed"
        assert updated.root_path == "C:/AI/projects/demo-renamed"
        assert updated.updated_at == updated_at
    finally:
        db.close()


def test_update_project_returns_none_for_missing_project(tmp_path):
    db = make_session(tmp_path)
    try:
        assert update_project(db, project_id="missing", name="ignored") is None
    finally:
        db.close()
