from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_EVAL_CASES_PATH = Path(__file__).with_name("cases.json")
REQUIRED_FIELDS = {
    "id",
    "category",
    "input_finding",
    "expected_constraints",
    "forbidden_outputs",
}
VALID_CATEGORIES = {"sast", "cve", "secret", "cce", "false_positive"}


@dataclass(frozen=True)
class EvalCase:
    id: str
    category: str
    input_finding: dict[str, Any]
    expected_constraints: list[str]
    forbidden_outputs: list[str]


def _validate_string_list(value: Any, field_name: str, case_id: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"Eval case {case_id} field '{field_name}' must be a non-empty list")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"Eval case {case_id} field '{field_name}' must contain non-empty strings")
    return value


def _validate_case(raw_case: Any) -> EvalCase:
    if not isinstance(raw_case, dict):
        raise ValueError("Each eval case must be an object")

    missing = REQUIRED_FIELDS - set(raw_case)
    case_id = raw_case.get("id", "<missing>")
    if missing:
        raise ValueError(f"Eval case {case_id} is missing required fields: {sorted(missing)}")

    if not isinstance(raw_case["id"], str) or not raw_case["id"].strip():
        raise ValueError("Eval case id must be a non-empty string")
    if not isinstance(raw_case["category"], str) or raw_case["category"] not in VALID_CATEGORIES:
        raise ValueError(
            f"Eval case {raw_case['id']} category must be one of {sorted(VALID_CATEGORIES)}"
        )
    if not isinstance(raw_case["input_finding"], dict) or not raw_case["input_finding"]:
        raise ValueError(f"Eval case {raw_case['id']} input_finding must be a non-empty object")

    return EvalCase(
        id=raw_case["id"],
        category=raw_case["category"],
        input_finding=raw_case["input_finding"],
        expected_constraints=_validate_string_list(
            raw_case["expected_constraints"],
            "expected_constraints",
            raw_case["id"],
        ),
        forbidden_outputs=_validate_string_list(
            raw_case["forbidden_outputs"],
            "forbidden_outputs",
            raw_case["id"],
        ),
    )


def validate_eval_cases(raw_cases: Any) -> list[EvalCase]:
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("Eval cases must be a non-empty list")

    cases = [_validate_case(raw_case) for raw_case in raw_cases]
    ids = [case.id for case in cases]
    duplicate_ids = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicate_ids:
        raise ValueError(f"Duplicate eval case ids: {duplicate_ids}")
    return cases


def load_eval_cases(path: str | Path | None = None) -> list[EvalCase]:
    cases_path = Path(path) if path is not None else DEFAULT_EVAL_CASES_PATH
    raw_cases = json.loads(cases_path.read_text(encoding="utf-8"))
    return validate_eval_cases(raw_cases)
