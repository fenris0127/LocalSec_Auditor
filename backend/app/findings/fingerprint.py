from __future__ import annotations

from hashlib import sha256
import json
from typing import Any


FINGERPRINT_FIELDS = (
    "scanner",
    "category",
    "cve",
    "cwe",
    "rule_id",
    "file_path",
    "line",
    "component",
)


def _get_field(finding: Any, field: str) -> Any:
    if isinstance(finding, dict):
        return finding.get(field)
    return getattr(finding, field, None)


def _normalize_value(value: Any) -> str | int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return text.lower() if text else None


def _fingerprint_payload(finding: Any) -> dict[str, str | int | None]:
    return {
        field: _normalize_value(_get_field(finding, field))
        for field in FINGERPRINT_FIELDS
    }


def generate_finding_fingerprint(finding: Any) -> str:
    payload = _fingerprint_payload(finding)
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"fp_{sha256(serialized.encode('utf-8')).hexdigest()}"
