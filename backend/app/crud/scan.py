from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scan import Scan


def create_scan(
    db: Session,
    *,
    scan_id: str,
    project_name: str,
    target_path: str,
    status: str,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    created_at: datetime | None = None,
) -> Scan:
    scan = Scan(
        id=scan_id,
        project_name=project_name,
        target_path=target_path,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        created_at=created_at or datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, scan_id: str) -> Scan | None:
    return db.get(Scan, scan_id)


def list_scans(db: Session) -> list[Scan]:
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc())))
