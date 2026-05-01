from __future__ import annotations

import json
from hashlib import sha1
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from app.schemas.finding import FindingCreate


def _make_finding_id(scan_id: str, rule_id: str, file_path: str | None, line: int | None) -> str:
    fingerprint = f"{scan_id}|{rule_id}|{file_path or ''}|{line or ''}"
    digest = sha1(fingerprint.encode("utf-8")).hexdigest()
    return f"finding_{uuid5(NAMESPACE_URL, digest).hex}"


def normalize_gitleaks(raw_json_path: str, scan_id: str) -> list[FindingCreate]:
    payload = json.loads(Path(raw_json_path).read_text(encoding="utf-8"))
    findings: list[FindingCreate] = []

    for result in payload:
        rule_id = result.get("RuleID", "")
        file_path = result.get("File")
        line = result.get("StartLine")

        findings.append(
            FindingCreate(
                id=_make_finding_id(scan_id, rule_id, file_path, line),
                scan_id=scan_id,
                category="secret",
                scanner="gitleaks",
                severity="high",
                title=f"Secret detected: {rule_id}",
                file_path=file_path,
                line=line,
                raw_json_path=raw_json_path,
                status="open",
            )
        )

    return findings
