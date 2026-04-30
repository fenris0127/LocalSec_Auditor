from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding


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
    file_path: str | None = None,
    line: int | None = None,
    component: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    raw_json_path: str | None = None,
    llm_summary: str | None = None,
) -> Finding:
    finding = Finding(
        id=finding_id,
        scan_id=scan_id,
        category=category,
        scanner=scanner,
        severity=severity,
        title=title,
        file_path=file_path,
        line=line,
        component=component,
        cve=cve,
        cwe=cwe,
        raw_json_path=raw_json_path,
        llm_summary=llm_summary,
        status=status,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def list_findings_by_scan(db: Session, scan_id: str) -> list[Finding]:
    statement = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
    return list(db.scalars(statement))


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
