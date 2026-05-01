from __future__ import annotations

import json
from hashlib import sha1
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from app.schemas.finding import FindingCreate


def _make_finding_id(scan_id: str, cve: str, component: str | None, installed_version: str | None) -> str:
    fingerprint = f"{scan_id}|{cve}|{component or ''}|{installed_version or ''}"
    digest = sha1(fingerprint.encode("utf-8")).hexdigest()
    return f"finding_{uuid5(NAMESPACE_URL, digest).hex}"


def _fixed_version(match: dict) -> str | None:
    versions = (
        match.get("vulnerability", {})
        .get("fix", {})
        .get("versions", [])
    )
    if not versions:
        return None
    return ", ".join(str(version) for version in versions if str(version).strip()) or None


def normalize_grype(raw_json_path: str, scan_id: str) -> list[FindingCreate]:
    payload = json.loads(Path(raw_json_path).read_text(encoding="utf-8"))
    findings: list[FindingCreate] = []

    for match in payload.get("matches", []) or []:
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        cve = vulnerability.get("id", "")
        component = artifact.get("name")
        installed_version = artifact.get("version")
        fixed_version = _fixed_version(match)
        severity = (vulnerability.get("severity") or "medium").lower()
        title = cve or "Grype vulnerability"
        if component:
            title = f"{title} in {component}"
        if fixed_version:
            title = f"{title} (fixed: {fixed_version})"

        findings.append(
            FindingCreate(
                id=_make_finding_id(scan_id, cve, component, installed_version),
                scan_id=scan_id,
                category="cve",
                scanner="grype",
                severity=severity,
                title=title,
                component=component,
                installed_version=installed_version,
                fixed_version=fixed_version,
                cve=cve,
                raw_json_path=raw_json_path,
                status="open",
            )
        )

    return findings
