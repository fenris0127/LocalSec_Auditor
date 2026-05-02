from __future__ import annotations

from hashlib import sha1
from pathlib import Path
import re
from uuid import NAMESPACE_URL, uuid5

from app.schemas.finding import FindingCreate


_BRACKET_RESULT_RE = re.compile(r"^\[(WARNING|SUGGESTION)\]\s*(.+)$", re.IGNORECASE)
_REPORT_DAT_RE = re.compile(r"^(warning|suggestion)\[\]=(.+)$", re.IGNORECASE)


def _make_finding_id(scan_id: str, kind: str, title: str, index: int) -> str:
    fingerprint = f"{scan_id}|lynis|{kind.lower()}|{title}|{index}"
    digest = sha1(fingerprint.encode("utf-8")).hexdigest()
    return f"finding_{uuid5(NAMESPACE_URL, digest).hex}"


def _severity(kind: str) -> str:
    if kind.lower() == "warning":
        return "medium"
    return "medium"


def _strip_control_tokens(value: str) -> str:
    return value.strip().strip("'\"").strip()


def _extract_results(raw_text: str) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        bracket_match = _BRACKET_RESULT_RE.match(stripped)
        if bracket_match:
            results.append(
                (
                    bracket_match.group(1).lower(),
                    _strip_control_tokens(bracket_match.group(2)),
                )
            )
            continue

        report_dat_match = _REPORT_DAT_RE.match(stripped)
        if report_dat_match:
            results.append(
                (
                    report_dat_match.group(1).lower(),
                    _strip_control_tokens(report_dat_match.group(2)),
                )
            )

    return [(kind, title) for kind, title in results if title]


def normalize_lynis(raw_result_path: str, scan_id: str) -> list[FindingCreate]:
    raw_text = Path(raw_result_path).read_text(encoding="utf-8")
    findings: list[FindingCreate] = []

    for index, (kind, title) in enumerate(_extract_results(raw_text)):
        findings.append(
            FindingCreate(
                id=_make_finding_id(scan_id, kind, title, index),
                scan_id=scan_id,
                category="config",
                scanner="lynis",
                severity=_severity(kind),
                title=title,
                rule_id=f"lynis:{kind}",
                raw_json_path=raw_result_path,
                status="open",
            )
        )

    return findings
