from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class CveDedupKey:
    category: str
    cve: str | None
    component: str | None
    installed_version: str | None


def build_cve_dedup_key(
    *,
    category: str,
    cve: str | None,
    component: str | None,
    installed_version: str | None,
) -> CveDedupKey | None:
    if category.lower() != "cve" or not cve or not component:
        return None
    return CveDedupKey(
        category=category.lower(),
        cve=cve.strip().upper(),
        component=component.strip().lower(),
        installed_version=(installed_version or "").strip().lower() or None,
    )


def detected_by_to_json(scanners: list[str]) -> str:
    unique_scanners = []
    for scanner in scanners:
        if scanner and scanner not in unique_scanners:
            unique_scanners.append(scanner)
    return json.dumps(unique_scanners)


def detected_by_from_json(value: str | None) -> list[str]:
    if not value:
        return []
    payload = json.loads(value)
    if not isinstance(payload, list):
        return []
    return [str(scanner) for scanner in payload]
