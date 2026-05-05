from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.scan import Scan


def _normalize_count_key(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    return normalized or "unknown"


def _scan_payload(scan: Scan, finding_count: int) -> dict[str, Any]:
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "project_name": scan.project_name,
        "target_path": scan.target_path,
        "status": scan.status,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "finding_count": finding_count,
    }


def _latest_project_payload(scan: Scan) -> dict[str, str | datetime | None]:
    return {
        "project_id": scan.project_id,
        "project_name": scan.project_name,
        "latest_scan_id": scan.id,
        "latest_scan_status": scan.status,
        "latest_scan_created_at": scan.created_at,
    }


def build_dashboard_summary(db: Session, *, recent_limit: int = 10) -> dict[str, Any]:
    scans = list(db.scalars(select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc())))
    scan_ids = [scan.id for scan in scans]
    finding_counts_by_scan = Counter(
        finding.scan_id
        for finding in db.scalars(select(Finding).where(Finding.scan_id.in_(scan_ids))).all()
    ) if scan_ids else Counter()

    severity_counts = Counter(
        _normalize_count_key(severity)
        for severity in db.scalars(select(Finding.severity)).all()
    )

    latest_by_project: dict[str, Scan] = {}
    for scan in scans:
        project_key = scan.project_id or f"project_name:{scan.project_name}"
        if project_key not in latest_by_project:
            latest_by_project[project_key] = scan

    return {
        "recent_scans": [
            _scan_payload(scan, finding_counts_by_scan[scan.id])
            for scan in scans[:recent_limit]
        ],
        "severity_counts": dict(sorted(severity_counts.items())),
        "project_latest_scans": [
            _latest_project_payload(scan)
            for scan in latest_by_project.values()
        ],
    }
