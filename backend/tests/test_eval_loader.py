import pytest

from evals.loader import VALID_CATEGORIES, load_eval_cases, validate_eval_cases


def test_load_default_eval_cases_returns_five_samples():
    cases = load_eval_cases()

    assert len(cases) == 5


def test_sample_eval_cases_are_valid_and_cover_required_categories():
    cases = load_eval_cases()

    assert {case.category for case in cases} == {
        "sast",
        "cve",
        "secret",
        "cce",
        "false_positive",
    }
    assert all(case.id for case in cases)
    assert all(case.input_finding for case in cases)
    assert all(case.expected_constraints for case in cases)
    assert all(case.forbidden_outputs for case in cases)
    assert all(case.category in VALID_CATEGORIES for case in cases)


def test_eval_case_ids_are_unique():
    cases = load_eval_cases()

    assert len({case.id for case in cases}) == len(cases)


def test_loader_rejects_missing_required_field():
    raw_cases = [
        {
            "id": "eval-invalid-001",
            "category": "sast",
            "input_finding": {"scanner": "semgrep"},
            "expected_constraints": ["Must be grounded in scanner evidence."],
        }
    ]

    with pytest.raises(ValueError, match="forbidden_outputs"):
        validate_eval_cases(raw_cases)


def test_loader_rejects_duplicate_ids():
    raw_cases = [
        {
            "id": "eval-duplicate",
            "category": "sast",
            "input_finding": {"scanner": "semgrep"},
            "expected_constraints": ["Must be grounded in scanner evidence."],
            "forbidden_outputs": ["Do not invent a CVE."],
        },
        {
            "id": "eval-duplicate",
            "category": "cve",
            "input_finding": {"scanner": "trivy"},
            "expected_constraints": ["Must use only input CVEs."],
            "forbidden_outputs": ["Do not add extra CVEs."],
        },
    ]

    with pytest.raises(ValueError, match="Duplicate eval case ids"):
        validate_eval_cases(raw_cases)
