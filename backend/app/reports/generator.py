from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

from app.crud.finding import list_findings_by_scan
from app.crud.scan import get_scan
from app.core.config import PROJECT_ROOT
from app.db.database import SessionLocal
from app.llm.secret_masking import mask_secret_text
from app.models.finding import Finding
from app.services.scan_dirs import create_scan_dirs


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _display(value: object) -> str:
    if value is None:
        return "N/A"
    text = mask_secret_text(value).strip()
    return text if text else "N/A"


def _format_counter(counter: Counter[str]) -> list[str]:
    if not counter:
        return ["- None"]
    return [f"- {key}: {counter[key]}" for key in sorted(counter)]


def _priority_key(finding: Finding) -> tuple[int, str]:
    severity = (finding.severity or "").lower()
    return (SEVERITY_ORDER.get(severity, 99), finding.id)


def _render_priority_list(findings: Iterable[Finding]) -> list[str]:
    ordered = sorted(findings, key=_priority_key)
    if not ordered:
        return ["- No findings"]

    lines = []
    for finding in ordered:
        location = _display(finding.file_path)
        if finding.line is not None:
            location = f"{location}:{finding.line}"
        lines.append(
            f"- [{_display(finding.severity)}] {_display(finding.title)} "
            f"({finding.scanner}, {location})"
        )
    return lines


def _render_finding_detail(finding: Finding) -> list[str]:
    lines = [
        f"### {_display(finding.title)}",
        "",
        f"- ID: {finding.id}",
        f"- Scanner: {_display(finding.scanner)}",
        f"- Category: {_display(finding.category)}",
        f"- Severity: {_display(finding.severity)}",
        f"- Status: {_display(finding.status)}",
        f"- File: {_display(finding.file_path)}",
        f"- Line: {_display(finding.line)}",
        f"- Component: {_display(finding.component)}",
        f"- CVE: {_display(finding.cve)}",
        f"- CWE: {_display(finding.cwe)}",
        f"- Raw JSON: {_display(finding.raw_json_path)}",
    ]

    if finding.llm_summary:
        lines.extend(["", "**LLM Summary**", "", mask_secret_text(finding.llm_summary).strip()])

    lines.append("")
    return lines


def _render_report(scan, findings: list[Finding]) -> str:
    severity_counts = Counter((finding.severity or "unknown").lower() for finding in findings)
    category_counts = Counter((finding.category or "unknown").lower() for finding in findings)

    lines = [
        f"# LocalSec Auditor Report: {scan.id}",
        "",
        "## Scan Information",
        "",
        f"- Project: {_display(scan.project_name)}",
        f"- Target Path: {_display(scan.target_path)}",
        f"- Status: {_display(scan.status)}",
        f"- Created At: {_display(scan.created_at)}",
        f"- Started At: {_display(scan.started_at)}",
        f"- Finished At: {_display(scan.finished_at)}",
        "",
        "## Summary",
        "",
        f"- Total Findings: {len(findings)}",
        "",
        "### Severity Statistics",
        "",
        *_format_counter(severity_counts),
        "",
        "### Category Statistics",
        "",
        *_format_counter(category_counts),
        "",
        "## Priority List",
        "",
        *_render_priority_list(findings),
        "",
        "## Finding Details",
        "",
    ]

    if findings:
        for finding in sorted(findings, key=_priority_key):
            lines.extend(_render_finding_detail(finding))
    else:
        lines.append("No findings.")

    return "\n".join(lines).rstrip() + "\n"


def get_markdown_report_path(scan_id: str) -> Path:
    return PROJECT_ROOT / "data" / "scans" / scan_id / "reports" / "report.md"


def generate_markdown_report(scan_id: str) -> Path:
    db = SessionLocal()
    try:
        scan = get_scan(db, scan_id)
        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")
        findings = list_findings_by_scan(db, scan_id)
        report = _render_report(scan, findings)
    finally:
        db.close()

    paths = create_scan_dirs(scan_id)
    report_path = paths["reports"] / "report.md"
    report_path.write_text(report, encoding="utf-8")
    return report_path
