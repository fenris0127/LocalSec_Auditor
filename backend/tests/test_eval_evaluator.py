from evals.evaluator import evaluate_llm_response
from evals.loader import EvalCase, load_eval_cases


def make_case(
    category="cve",
    input_finding=None,
    forbidden_outputs=None,
) -> EvalCase:
    return EvalCase(
        id="eval-test",
        category=category,
        input_finding=input_finding
        or {
            "category": "cve",
            "scanner": "trivy",
            "title": "Vulnerable OpenSSL package",
            "cve": "CVE-2024-5535",
        },
        expected_constraints=["Must stay grounded in scanner evidence."],
        forbidden_outputs=forbidden_outputs or ["FORBIDDEN_PHRASE"],
    )


GOOD_RESPONSE = """
1. 요약
Scanner evidence reports CVE-2024-5535 in the OpenSSL package.

2. 위험한 이유
The vulnerable dependency may expose the application to known package risk.

3. 조치 방법
Update or rebuild the affected package from a trusted source.

4. 검증 방법
Verify by rerunning the scanner and confirming CVE-2024-5535 no longer appears.

5. 오탐 가능성
False positive likelihood is possible but should be checked against package metadata.
"""


def test_good_response_passes():
    result = evaluate_llm_response(make_case(), GOOD_RESPONSE)

    assert result.passed is True
    assert result.failures == []


def test_response_fails_when_required_sections_are_missing():
    result = evaluate_llm_response(make_case(), "Only a short summary.")

    assert result.passed is False
    assert "missing required section: risk" in result.failures
    assert "missing required section: verification" in result.failures


def test_response_fails_when_forbidden_output_is_present():
    result = evaluate_llm_response(make_case(), GOOD_RESPONSE + "\nFORBIDDEN_PHRASE")

    assert result.passed is False
    assert "contains forbidden output: FORBIDDEN_PHRASE" in result.failures


def test_response_fails_when_raw_secret_like_value_is_present():
    secret_case = make_case(
        category="secret",
        input_finding={
            "category": "secret",
            "scanner": "gitleaks",
            "title": "Secret detected",
            "metadata": {"secret_value": "sk_test_1234567890abcdef1234567890abcdef"},
        },
    )

    result = evaluate_llm_response(
        secret_case,
        GOOD_RESPONSE.replace("CVE-2024-5535", "")
        + "\nsk_test_1234567890abcdef1234567890abcdef",
    )

    assert result.passed is False
    assert "contains raw secret-like value" in result.failures


def test_response_allows_redacted_secret_placeholder():
    secret_case = make_case(
        category="secret",
        input_finding={
            "category": "secret",
            "scanner": "gitleaks",
            "title": "Secret detected",
            "metadata": {"secret_preview": "[REDACTED_SECRET]"},
        },
    )

    response = GOOD_RESPONSE.replace("CVE-2024-5535", "the scanner finding")
    result = evaluate_llm_response(secret_case, response + "\nSecret: [REDACTED_SECRET]")

    assert result.passed is True


def test_response_fails_when_it_invents_cve():
    result = evaluate_llm_response(make_case(), GOOD_RESPONSE + "\nAlso related: CVE-2099-9999")

    assert result.passed is False
    assert "contains CVE not present in input_finding: ['CVE-2099-9999']" in result.failures


def test_response_passes_when_action_references_input_component():
    case = make_case(
        input_finding={
            "category": "cve",
            "scanner": "trivy",
            "title": "Vulnerable OpenSSL package",
            "component": "openssl",
            "cve": "CVE-2024-5535",
        },
    )
    response = GOOD_RESPONSE.replace(
        "Update or rebuild the affected package from a trusted source.",
        "Update openssl from a trusted source.",
    )

    result = evaluate_llm_response(case, response)

    assert result.passed is True


def test_response_fails_when_action_references_package_not_in_input():
    case = make_case(
        input_finding={
            "category": "cve",
            "scanner": "trivy",
            "title": "Vulnerable OpenSSL package",
            "component": "openssl",
            "cve": "CVE-2024-5535",
        },
    )
    response = GOOD_RESPONSE.replace(
        "Update or rebuild the affected package from a trusted source.",
        "Update lodash from a trusted source.",
    )

    result = evaluate_llm_response(case, response)

    assert result.passed is False
    assert (
        "contains component/package not present in input_finding action: ['lodash']"
        in result.failures
    )


def test_false_positive_response_fails_when_certainty_is_used():
    fp_case = make_case(
        category="false_positive",
        input_finding={
            "category": "sast",
            "scanner": "semgrep",
            "title": "Potential hardcoded password in test fixture",
        },
    )

    result = evaluate_llm_response(fp_case, GOOD_RESPONSE + "\nThis is a false positive.")

    assert result.passed is False
    assert "states false positive as certain" in result.failures


def test_sample_eval_cases_can_be_evaluated_with_safe_response_template():
    cases = load_eval_cases()

    for case in cases:
        cve = case.input_finding.get("cve", "")
        response = GOOD_RESPONSE.replace("CVE-2024-5535", cve or "the scanner finding")
        result = evaluate_llm_response(case, response)

        assert result.passed is True, f"{case.id}: {result.failures}"
