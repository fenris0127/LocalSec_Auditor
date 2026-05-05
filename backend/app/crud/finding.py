from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.services.finding_dedup import (
    build_cve_dedup_key,
    detected_by_from_json,
    detected_by_to_json,
)


def _find_duplicate_cve_finding(
    db: Session,
    *,
    scan_id: str,
    category: str,
    cve: str | None,
    component: str | None,
    installed_version: str | None,
) -> Finding | None:
    dedup_key = build_cve_dedup_key(
        category=category,
        cve=cve,
        component=component,
        installed_version=installed_version,
    )
    if dedup_key is None:
        return None

    conditions = [
        Finding.scan_id == scan_id,
        Finding.status != "superseded",
        func.lower(Finding.category) == dedup_key.category,
        func.upper(Finding.cve) == dedup_key.cve,
        func.lower(Finding.component) == dedup_key.component,
    ]
    if dedup_key.installed_version is None:
        conditions.append(Finding.installed_version.is_(None))
    else:
        conditions.append(func.lower(Finding.installed_version) == dedup_key.installed_version)

    statement = select(Finding).where(*conditions)
    return db.scalars(statement).first()


def create_finding(
    db: Session,
    *,
    finding_id: str,
    scan_id: str,
    category: str,
    scanner: str,
    severity: str,
    title: str,
    status: str,
    rule_id: str | None = None,
    file_path: str | None = None,
    line: int | None = None,
    component: str | None = None,
    installed_version: str | None = None,
    fixed_version: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    cce_id: str | None = None,
    current_value: str | None = None,
    expected_value: str | None = None,
    raw_json_path: str | None = None,
    llm_summary: str | None = None,
    detected_by: list[str] | None = None,
) -> Finding:
    duplicate = _find_duplicate_cve_finding(
        db,
        scan_id=scan_id,
        category=category,
        cve=cve,
        component=component,
        installed_version=installed_version,
    )
    if duplicate is not None:
        existing_sources = detected_by_from_json(duplicate.detected_by)
        new_sources = detected_by or [scanner]
        duplicate.detected_by = detected_by_to_json([*existing_sources, *new_sources])
        if duplicate.fixed_version is None and fixed_version is not None:
            duplicate.fixed_version = fixed_version
        db.commit()
        db.refresh(duplicate)
        return duplicate

    finding = Finding(
        id=finding_id,
        scan_id=scan_id,
        category=category,
        scanner=scanner,
        severity=severity,
        title=title,
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        component=component,
        installed_version=installed_version,
        fixed_version=fixed_version,
        cve=cve,
        cwe=cwe,
        cce_id=cce_id,
        current_value=current_value,
        expected_value=expected_value,
        raw_json_path=raw_json_path,
        llm_summary=llm_summary,
        detected_by=detected_by_to_json(detected_by or [scanner]),
        status=status,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def list_findings_by_scan(db: Session, scan_id: str) -> list[Finding]:
    statement = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
    return list(db.scalars(statement))


def mark_findings_superseded_by_scanner(
    db: Session,
    *,
    scan_id: str,
    scanner: str,
) -> int:
    statement = select(Finding).where(
        Finding.scan_id == scan_id,
        Finding.scanner == scanner,
        Finding.status != "superseded",
    )
    findings = list(db.scalars(statement))
    for finding in findings:
        finding.status = "superseded"
    db.commit()
    return len(findings)


def get_finding(db: Session, finding_id: str) -> Finding | None:
    return db.get(Finding, finding_id)


def update_finding_llm_summary(
    db: Session,
    *,
    finding_id: str,
    llm_summary: str,
) -> Finding | None:
    finding = db.get(Finding, finding_id)
    if finding is None:
        return None

    finding.llm_summary = llm_summary
    db.commit()
    db.refresh(finding)
    return finding
