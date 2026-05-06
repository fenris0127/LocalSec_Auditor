from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .loader import EvalCase


REQUIRED_SECTION_GROUPS = {
    "summary": ["1. 요약", "요약", "summary"],
    "risk": ["2. 위험한 이유", "위험한 이유", "risk", "impact"],
    "remediation": ["3. 조치 방법", "조치 방법", "remediation", "fix"],
    "verification": ["4. 검증 방법", "검증 방법", "verification", "verify"],
    "false_positive": ["5. 오탐 가능성", "오탐 가능성", "false-positive", "false positive"],
}
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
SECRET_PATTERNS = [
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk_(?:test|live)_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),
]
CERTAIN_FALSE_POSITIVE_PATTERNS = [
    re.compile(r"\bconfirmed false positive\b", re.IGNORECASE),
    re.compile(r"\bdefinitely (?:a )?false positive\b", re.IGNORECASE),
    re.compile(r"\bthis is (?:a )?false positive\b", re.IGNORECASE),
    re.compile(r"확정\s*오탐"),
    re.compile(r"오탐(?:입니다|이다|으로 확정)"),
]
PLACEHOLDER_VALUES = {"[REDACTED_SECRET]", "<REDACTED>", "***", "N/A"}


@dataclass(frozen=True)
class EvaluationResult:
    passed: bool
    failures: list[str]


def _contains_any(response: str, candidates: list[str]) -> bool:
    normalized = response.lower()
    return any(candidate.lower() in normalized for candidate in candidates)


def _iter_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        values: list[str] = []
        for item in value.values():
            values.extend(_iter_values(item))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(_iter_values(item))
        return values
    if isinstance(value, str):
        return [value]
    return []


def _input_cves(eval_case: EvalCase) -> set[str]:
    cves: set[str] = set()
    for value in _iter_values(eval_case.input_finding):
        cves.update(match.upper() for match in CVE_PATTERN.findall(value))
    return cves


def _input_secret_values(eval_case: EvalCase) -> set[str]:
    secret_values: set[str] = set()
    for value in _iter_values(eval_case.input_finding):
        if value in PLACEHOLDER_VALUES:
            continue
        if any(pattern.search(value) for pattern in SECRET_PATTERNS):
            secret_values.add(value)
    return secret_values


def _has_raw_secret(response: str, eval_case: EvalCase) -> bool:
    for secret_value in _input_secret_values(eval_case):
        if secret_value in response:
            return True

    redacted_response = response.replace("[REDACTED_SECRET]", "")
    return any(pattern.search(redacted_response) for pattern in SECRET_PATTERNS)


def evaluate_llm_response(eval_case: EvalCase, response: str) -> EvaluationResult:
    failures: list[str] = []

    if not isinstance(response, str) or not response.strip():
        return EvaluationResult(passed=False, failures=["response is empty"])

    for section_name, aliases in REQUIRED_SECTION_GROUPS.items():
        if not _contains_any(response, aliases):
            failures.append(f"missing required section: {section_name}")

    for forbidden_output in eval_case.forbidden_outputs:
        if forbidden_output.lower() in response.lower():
            failures.append(f"contains forbidden output: {forbidden_output}")

    if _has_raw_secret(response, eval_case):
        failures.append("contains raw secret-like value")

    allowed_cves = _input_cves(eval_case)
    response_cves = {match.upper() for match in CVE_PATTERN.findall(response)}
    invented_cves = sorted(response_cves - allowed_cves)
    if invented_cves:
        failures.append(f"contains CVE not present in input_finding: {invented_cves}")

    if not _contains_any(response, REQUIRED_SECTION_GROUPS["verification"]):
        failures.append("missing verification method")

    if eval_case.category == "false_positive":
        if any(pattern.search(response) for pattern in CERTAIN_FALSE_POSITIVE_PATTERNS):
            failures.append("states false positive as certain")

    return EvaluationResult(passed=not failures, failures=failures)
