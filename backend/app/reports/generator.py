from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path
import re
from typing import Iterable

from app.crud.finding import list_findings_by_scan
from app.crud.scan import get_scan
from app.core.config import PROJECT_ROOT
from app.db.database import SessionLocal
from app.llm.secret_masking import mask_secret_text
from app.models.finding import Finding
from app.rag.retrieval import retrieve_context_for_finding
from app.rag.vector_store import VectorSearchResult
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


def _is_config_finding(finding: Finding) -> bool:
    return (finding.category or "").lower() in {"cce", "config"}


def _render_config_findings(findings: Iterable[Finding]) -> list[str]:
    config_findings = sorted(
        [finding for finding in findings if _is_config_finding(finding)],
        key=_priority_key,
    )
    if not config_findings:
        return ["No CCE/config findings."]

    lines = [
        "This section is for review only. It does not change system settings.",
        "Record the existing setting before any manual change, prepare a rollback plan, and re-run the same check to verify the result.",
        "",
    ]
    for finding in config_findings:
        lines.extend(
            [
                f"### {_display(finding.title)}",
                "",
                f"- ID: {finding.id}",
                f"- Scanner: {_display(finding.scanner)}",
                f"- Category: {_display(finding.category)}",
                f"- Severity: {_display(finding.severity)}",
                f"- Rule ID: {_display(finding.rule_id)}",
                f"- CCE ID: {_display(getattr(finding, 'cce_id', None))}",
                f"- Current Value: {_display(getattr(finding, 'current_value', None))}",
                f"- Expected Value: {_display(getattr(finding, 'expected_value', None))}",
                f"- Raw JSON: {_display(finding.raw_json_path)}",
                "",
                "**Rollback / Verification Guidance**",
                "",
                "- Rollback: save the original setting value and the file or command source before a reviewed manual change.",
                "- Verification: re-run the same scanner/profile after the manual change and confirm the finding is resolved.",
                "",
            ]
        )
    return lines


def _summarize_chunk_text(content: object, max_length: int = 240) -> str:
    text = " ".join(mask_secret_text(content).split())
    if not text:
        return "N/A"
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3].rstrip()}..."


def _source_label(context: VectorSearchResult) -> str:
    title = context.metadata.get("title")
    source_path = context.metadata.get("source_path")
    source_name = context.metadata.get("source_name")
    return _display(title or source_path or source_name)


def _chunk_summary(context: VectorSearchResult) -> str:
    summary = context.metadata.get("summary")
    return _summarize_chunk_text(summary or context.content)


def _render_reference_documents(contexts: Iterable[VectorSearchResult]) -> list[str]:
    references = list(contexts)
    lines = ["", "**근거 문서**", ""]
    if not references:
        return [*lines, "근거 문서 없음"]

    for context in references:
        lines.append(f"- Source: {_source_label(context)}")
        if context.metadata.get("title") and context.metadata.get("source_path"):
            lines.append(f"  - Path: {_display(context.metadata.get('source_path'))}")
        lines.append(f"  - Chunk: {_display(context.metadata.get('chunk_index'))}")
        lines.append(f"  - Summary: {_chunk_summary(context)}")
    return lines


def _render_finding_detail(
    finding: Finding,
    reference_contexts: Iterable[VectorSearchResult] | None = None,
) -> list[str]:
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

    lines.extend(_render_reference_documents(reference_contexts or []))
    lines.append("")
    return lines


def _render_report(
    scan,
    findings: list[Finding],
    reference_contexts: dict[str, list[VectorSearchResult]] | None = None,
) -> str:
    severity_counts = Counter((finding.severity or "unknown").lower() for finding in findings)
    category_counts = Counter((finding.category or "unknown").lower() for finding in findings)
    contexts_by_finding = reference_contexts or {}

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
        "## CCE / System Configuration Findings",
        "",
        *_render_config_findings(findings),
        "",
        "## Finding Details",
        "",
    ]

    if findings:
        for finding in sorted(findings, key=_priority_key):
            lines.extend(_render_finding_detail(finding, contexts_by_finding.get(finding.id)))
    else:
        lines.append("No findings.")

    return "\n".join(lines).rstrip() + "\n"


def _get_reference_contexts(db, finding: Finding) -> list[VectorSearchResult]:
    try:
        return retrieve_context_for_finding(finding, db=db)
    except Exception:
        return []


def get_markdown_report_path(scan_id: str) -> Path:
    return PROJECT_ROOT / "data" / "scans" / scan_id / "reports" / "report.md"


def get_html_report_path(scan_id: str) -> Path:
    return PROJECT_ROOT / "data" / "scans" / scan_id / "reports" / "report.html"


def _render_inline_markdown(value: str) -> str:
    text = escape(mask_secret_text(value))
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)


def _severity_class_for_line(line: str) -> str:
    lower = line.lower()
    match = re.search(r"\[(critical|high|medium|low|info)\]", lower)
    if match:
        return f" severity severity-{match.group(1)}"

    match = re.search(r"severity:\s*(critical|high|medium|low|info)", lower)
    if match:
        return f" severity severity-{match.group(1)}"

    return ""


def _markdown_to_html(markdown: str) -> str:
    body: list[str] = []
    in_list = False

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            body.append("</ul>")
            in_list = False

    for raw_line in markdown.splitlines():
        line = mask_secret_text(raw_line).rstrip()
        if not line:
            close_list()
            continue

        if line.startswith("#"):
            close_list()
            heading_level = min(len(line) - len(line.lstrip("#")), 6)
            heading_text = line[heading_level:].strip()
            body.append(f"<h{heading_level}>{_render_inline_markdown(heading_text)}</h{heading_level}>")
            continue

        if line.startswith("- "):
            if not in_list:
                body.append("<ul>")
                in_list = True
            class_name = _severity_class_for_line(line)
            class_attr = f' class="{class_name.strip()}"' if class_name else ""
            body.append(f"<li{class_attr}>{_render_inline_markdown(line[2:].strip())}</li>")
            continue

        close_list()
        body.append(f"<p>{_render_inline_markdown(line)}</p>")

    close_list()

    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="ko">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>LocalSec Auditor Report</title>",
            "<style>",
            "body{font-family:Arial,sans-serif;line-height:1.6;color:#17202a;margin:32px;max-width:1080px}",
            "h1,h2,h3{line-height:1.25}",
            "ul{padding-left:24px}",
            "li{margin:4px 0}",
            ".severity{font-weight:700}",
            ".severity-critical{color:#8a1f1f}",
            ".severity-high{color:#b33a1f}",
            ".severity-medium{color:#8a5a12}",
            ".severity-low{color:#1f5f4c}",
            ".severity-info{color:#405266}",
            "</style>",
            "</head>",
            "<body>",
            *body,
            "</body>",
            "</html>",
            "",
        ]
    )


def generate_markdown_report(scan_id: str) -> Path:
    db = SessionLocal()
    try:
        scan = get_scan(db, scan_id)
        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")
        findings = list_findings_by_scan(db, scan_id)
        reference_contexts = {
            finding.id: _get_reference_contexts(db, finding) for finding in findings
        }
        report = _render_report(scan, findings, reference_contexts)
    finally:
        db.close()

    paths = create_scan_dirs(scan_id)
    report_path = paths["reports"] / "report.md"
    report_path.write_text(report, encoding="utf-8")
    return report_path


def generate_html_report(scan_id: str) -> Path:
    markdown_path = generate_markdown_report(scan_id)
    markdown = markdown_path.read_text(encoding="utf-8")
    html = _markdown_to_html(markdown)

    paths = create_scan_dirs(scan_id)
    report_path = paths["reports"] / "report.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path
