from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crud.finding import list_findings_by_scan
from app.crud.scan import get_scan
from app.db.database import SessionLocal
from app.models.finding import Finding
from app.models.scan import Scan


@dataclass(frozen=True)
class FindingGroupStats:
    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]


@dataclass(frozen=True)
class ScanComparisonResult:
    base_scan_id: str
    target_scan_id: str
    new_findings: list[Finding]
    resolved_findings: list[Finding]
    persistent_findings: list[Finding]
    stats: dict[str, FindingGroupStats]


def _fingerprints(findings: list[Finding]) -> set[str]:
    return {finding.fingerprint for finding in findings if finding.fingerprint}


def _normalize_stat_key(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    return normalized or "unknown"


def _build_stats(findings: list[Finding]) -> FindingGroupStats:
    severity_counts = Counter(_normalize_stat_key(finding.severity) for finding in findings)
    category_counts = Counter(_normalize_stat_key(finding.category) for finding in findings)
    return FindingGroupStats(
        total=len(findings),
        by_severity=dict(sorted(severity_counts.items())),
        by_category=dict(sorted(category_counts.items())),
    )


def _compare_scans(db: Session, *, base_scan_id: str, target_scan_id: str) -> ScanComparisonResult:
    base_scan = get_scan(db, base_scan_id)
    target_scan = get_scan(db, target_scan_id)
    if base_scan is None:
        raise ValueError(f"base scan not found: {base_scan_id}")
    if target_scan is None:
        raise ValueError(f"target scan not found: {target_scan_id}")
    if not base_scan.project_id or not target_scan.project_id:
        raise ValueError("scan comparison requires project_id on both scans")
    if base_scan.project_id != target_scan.project_id:
        raise ValueError("scan comparison requires scans from the same project_id")

    base_findings = list_findings_by_scan(db, base_scan_id)
    target_findings = list_findings_by_scan(db, target_scan_id)
    base_fingerprints = _fingerprints(base_findings)
    target_fingerprints = _fingerprints(target_findings)

    new_findings = [
        finding
        for finding in target_findings
        if finding.fingerprint and finding.fingerprint not in base_fingerprints
    ]
    resolved_findings = [
        finding
        for finding in base_findings
        if finding.fingerprint and finding.fingerprint not in target_fingerprints
    ]
    persistent_findings = [
        finding
        for finding in target_findings
        if finding.fingerprint and finding.fingerprint in base_fingerprints
    ]

    return ScanComparisonResult(
        base_scan_id=base_scan_id,
        target_scan_id=target_scan_id,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        persistent_findings=persistent_findings,
        stats={
            "new_findings": _build_stats(new_findings),
            "resolved_findings": _build_stats(resolved_findings),
            "persistent_findings": _build_stats(persistent_findings),
        },
    )


def _get_previous_scan(db: Session, *, scan_id: str) -> Scan | None:
    scan = get_scan(db, scan_id)
    if scan is None:
        raise ValueError(f"scan not found: {scan_id}")
    if not scan.project_id:
        raise ValueError("previous scan lookup requires project_id on scan")

    statement = (
        select(Scan)
        .where(
            Scan.project_id == scan.project_id,
            Scan.created_at < scan.created_at,
        )
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    )
    return db.scalars(statement).first()


def get_previous_scan(scan_id: str, db: Session | None = None) -> Scan | None:
    if db is not None:
        return _get_previous_scan(db, scan_id=scan_id)

    local_db = SessionLocal()
    try:
        return _get_previous_scan(local_db, scan_id=scan_id)
    finally:
        local_db.close()


def compare_scans(
    base_scan_id: str,
    target_scan_id: str,
    db: Session | None = None,
) -> ScanComparisonResult:
    if db is not None:
        return _compare_scans(db, base_scan_id=base_scan_id, target_scan_id=target_scan_id)

    local_db = SessionLocal()
    try:
        return _compare_scans(local_db, base_scan_id=base_scan_id, target_scan_id=target_scan_id)
    finally:
        local_db.close()
