from __future__ import annotations

import json
from hashlib import sha1
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from app.schemas.finding import FindingCreate


SEVERITY_MAP = {
    "ERROR": "high",
    "HIGH": "high",
    "WARNING": "medium",
    "MEDIUM": "medium",
    "INFO": "low",
    "LOW": "low",
}


def _normalize_severity(raw: str | None) -> str:
    if not raw:
        return "medium"
    return SEVERITY_MAP.get(raw.upper(), "medium")


def _make_finding_id(scan_id: str, check_id: str, path: str | None, line: int | None) -> str:
    fingerprint = f"{scan_id}|{check_id}|{path or ''}|{line or ''}"
    digest = sha1(fingerprint.encode("utf-8")).hexdigest()
    return f"finding_{uuid5(NAMESPACE_URL, digest).hex}"


def normalize_semgrep(raw_json_path: str, scan_id: str) -> list[FindingCreate]:
    payload = json.loads(Path(raw_json_path).read_text(encoding="utf-8"))
    findings: list[FindingCreate] = []

    for result in payload.get("results", []):
        check_id = result.get("check_id", "")
        path = result.get("path")
        start = result.get("start") or {}
        extra = result.get("extra") or {}
        line = start.get("line")
        severity = _normalize_severity(extra.get("severity"))
        title = extra.get("message") or check_id or "Semgrep finding"

        findings.append(
            FindingCreate(
                id=_make_finding_id(scan_id, check_id, path, line),
                scan_id=scan_id,
                category="sast",
                scanner="semgrep",
                severity=severity,
                title=title,
                file_path=path,
                line=line,
                raw_json_path=raw_json_path,
                status="open",
            )
        )

    return findings
