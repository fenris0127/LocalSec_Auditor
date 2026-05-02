from __future__ import annotations

from hashlib import sha1
from pathlib import Path
import xml.etree.ElementTree as ET
from uuid import NAMESPACE_URL, uuid5

from app.schemas.finding import FindingCreate


SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
    "unknown": "medium",
}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _children_by_name(node: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(node) if _local_name(child.tag) == name]


def _first_child_text(node: ET.Element, name: str) -> str | None:
    for child in _children_by_name(node, name):
        text = (child.text or "").strip()
        if text:
            return text
    return None


def _normalize_severity(value: str | None) -> str:
    if not value:
        return "medium"
    return SEVERITY_MAP.get(value.strip().lower(), "medium")


def _make_finding_id(scan_id: str, rule_id: str) -> str:
    fingerprint = f"{scan_id}|openscap|{rule_id}"
    digest = sha1(fingerprint.encode("utf-8")).hexdigest()
    return f"finding_{uuid5(NAMESPACE_URL, digest).hex}"


def _rule_metadata(root: ET.Element) -> dict[str, dict[str, str | None]]:
    rules: dict[str, dict[str, str | None]] = {}
    for node in root.iter():
        if _local_name(node.tag) != "Rule":
            continue

        rule_id = node.attrib.get("id")
        if not rule_id:
            continue

        cce_id = None
        for ident in _children_by_name(node, "ident"):
            ident_text = (ident.text or "").strip()
            ident_system = ident.attrib.get("system", "")
            if ident_text.startswith("CCE-") or "cce" in ident_system.lower():
                cce_id = ident_text or None
                break

        rules[rule_id] = {
            "title": _first_child_text(node, "title"),
            "severity": node.attrib.get("severity"),
            "cce_id": cce_id,
        }
    return rules


def normalize_openscap(raw_result_path: str, scan_id: str) -> list[FindingCreate]:
    root = ET.parse(Path(raw_result_path)).getroot()
    rules = _rule_metadata(root)
    findings: list[FindingCreate] = []

    for node in root.iter():
        if _local_name(node.tag) != "rule-result":
            continue

        rule_id = node.attrib.get("idref")
        result = _first_child_text(node, "result")
        if not rule_id or result != "fail":
            continue

        metadata = rules.get(rule_id, {})
        title = metadata.get("title") or rule_id

        findings.append(
            FindingCreate(
                id=_make_finding_id(scan_id, rule_id),
                scan_id=scan_id,
                category="cce",
                scanner="openscap",
                severity=_normalize_severity(metadata.get("severity")),
                title=title,
                rule_id=rule_id,
                cce_id=metadata.get("cce_id"),
                raw_json_path=raw_result_path,
                status="open",
            )
        )

    return findings
