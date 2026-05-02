from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.project import Project


def create_project(
    db: Session,
    *,
    project_id: str,
    name: str,
    root_path: str,
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> Project:
    now = created_at or datetime.utcnow()
    project = Project(
        id=project_id,
        name=name,
        root_path=root_path,
        created_at=created_at or now,
        updated_at=updated_at or now,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def get_project(db: Session, project_id: str) -> Project | None:
    return db.get(Project, project_id)


def list_projects(db: Session) -> list[Project]:
    return list(db.scalars(select(Project).order_by(Project.created_at.desc())))


def update_project(
    db: Session,
    *,
    project_id: str,
    name: str | None = None,
    root_path: str | None = None,
    updated_at: datetime | None = None,
) -> Project | None:
    project = db.get(Project, project_id)
    if project is None:
        return None

    if name is not None:
        project.name = name
    if root_path is not None:
        project.root_path = root_path
    project.updated_at = updated_at or datetime.utcnow()

    db.commit()
    db.refresh(project)
    return project
