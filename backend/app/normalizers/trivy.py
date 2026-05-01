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


def normalize_trivy(raw_json_path: str, scan_id: str) -> list[FindingCreate]:
    payload = json.loads(Path(raw_json_path).read_text(encoding="utf-8"))
    findings: list[FindingCreate] = []

    for result in payload.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            cve = vuln.get("VulnerabilityID", "")
            component = vuln.get("PkgName")
            installed_version = vuln.get("InstalledVersion")
            fixed_version = vuln.get("FixedVersion")
            severity = (vuln.get("Severity") or "medium").lower()
            base_title = vuln.get("Title") or cve or "Trivy vulnerability"
            title = base_title
            if fixed_version:
                title = f"{base_title} (fixed: {fixed_version})"

            findings.append(
                FindingCreate(
                    id=_make_finding_id(scan_id, cve, component, installed_version),
                    scan_id=scan_id,
                    category="cve",
                    scanner="trivy",
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
