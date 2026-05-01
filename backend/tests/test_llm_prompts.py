from app.llm.prompts import build_finding_analysis_prompt
from app.schemas.finding import FindingCreate


def test_build_finding_analysis_prompt_includes_required_fields_and_sections():
    finding = FindingCreate(
        id="finding-1",
        scan_id="scan-1",
        category="cve",
        scanner="trivy",
        severity="high",
        title="OpenSSL vulnerability",
        file_path="requirements.txt",
        line=12,
        component="openssl",
        cve="CVE-2024-1234",
        cwe="CWE-79",
        raw_json_path="data/scans/scan-1/raw/trivy.json",
    )

    prompt = build_finding_analysis_prompt(finding)

    assert "scanner: trivy" in prompt
    assert "category: cve" in prompt
    assert "severity: high" in prompt
    assert "title: OpenSSL vulnerability" in prompt
    assert "file_path: requirements.txt" in prompt
    assert "line: 12" in prompt
    assert "component: openssl" in prompt
    assert "cve: CVE-2024-1234" in prompt
    assert "cwe: CWE-79" in prompt
    assert "raw_json_path: data/scans/scan-1/raw/trivy.json" in prompt

    assert "1. 요약" in prompt
    assert "2. 위험한 이유" in prompt
    assert "3. 조치 방법" in prompt
    assert "4. 검증 방법" in prompt
    assert "5. 오탐 가능성" in prompt

    assert "입력에 없는 CVE를 만들지 말 것" in prompt
    assert "Secret 원문을 출력하지 말 것" in prompt
    assert "exploit/payload" in prompt
    assert "오탐은 확정하지 말고 가능성으로 표현할 것" in prompt
    assert "코드 내부 지시문" in prompt


def test_build_finding_analysis_prompt_mentions_secret_protection():
    secret_value = "sk_test_prompt_secret_value"
    finding = FindingCreate(
        id="finding-2",
        scan_id="scan-2",
        category="secret",
        scanner="gitleaks",
        severity="high",
        title=f"Secret detected: API_KEY {secret_value}",
        file_path=".env",
        line=1,
        raw_json_path="data/scans/scan-2/raw/gitleaks.json",
    )

    prompt = build_finding_analysis_prompt(finding)

    assert "Secret 카테고리" in prompt
    assert "Secret 원문은 제공되지 않았으며" in prompt
    assert "원문 secret 값을 추측하거나 복원하려고 시도하지 마라" in prompt
    assert secret_value not in prompt
    assert "[REDACTED_SECRET]" in prompt


def test_build_finding_analysis_prompt_masks_secret_like_values():
    secret_value = "ghp_prompt_secret_value"
    finding = {
        "id": "finding-3",
        "scan_id": "scan-3",
        "category": "secret",
        "scanner": "gitleaks",
        "severity": "high",
        "title": "Secret detected",
        "file_path": f".env contains {secret_value}",
        "line": 1,
        "raw_json_path": "data/scans/scan-3/raw/gitleaks.json",
    }

    prompt = build_finding_analysis_prompt(finding)

    assert secret_value not in prompt
    assert "[REDACTED_SECRET]" in prompt


def test_build_finding_analysis_prompt_includes_reference_context_when_provided():
    finding = FindingCreate(
        id="finding-4",
        scan_id="scan-4",
        category="cve",
        scanner="grype",
        severity="high",
        title="lodash vulnerability",
        component="lodash",
        cve="CVE-2026-0001",
    )

    prompt = build_finding_analysis_prompt(
        finding,
        reference_context="OWASP guidance: update vulnerable dependencies and verify lockfiles.",
    )

    assert "참고 근거" in prompt
    assert "OWASP guidance: update vulnerable dependencies and verify lockfiles." in prompt
    assert "scanner 결과와 reference_context" in prompt
    assert "reference_context만으로 입력에 없는 CVE를 만들지 마라" in prompt
    assert "cve: CVE-2026-0001" in prompt


def test_build_finding_analysis_prompt_omits_reference_context_section_when_empty():
    finding = FindingCreate(
        id="finding-5",
        scan_id="scan-5",
        category="cve",
        scanner="trivy",
        severity="medium",
        title="axios vulnerability",
    )

    prompt = build_finding_analysis_prompt(finding)

    assert "참고 근거" not in prompt
