from pathlib import Path

from app.normalizers.gitleaks import normalize_gitleaks

SECRET_VALUES = [
    "sk_test_1234567890",
    "-----BEGIN PRIVATE KEY-----FAKE-----END PRIVATE KEY-----",
]


def test_normalize_gitleaks_creates_secret_findings_without_secret_value():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_gitleaks.json"

    findings = normalize_gitleaks(str(fixture_path), "scan_002")

    assert len(findings) == 2
    assert findings[0].scan_id == "scan_002"
    assert findings[0].category == "secret"
    assert findings[0].scanner == "gitleaks"
    assert findings[0].severity == "high"
    assert findings[0].title == "Secret detected: generic-api-key"
    assert findings[0].file_path == "src/settings.py"
    assert findings[0].line == 14
    assert findings[0].raw_json_path == str(fixture_path)
    assert findings[0].status == "open"

    for finding in findings:
        serialized = finding.model_dump_json()
        for secret_value in SECRET_VALUES:
            assert secret_value not in serialized


def test_normalize_gitleaks_finding_db_payload_excludes_secret_fields():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_gitleaks.json"

    findings = normalize_gitleaks(str(fixture_path), "scan_002")

    for finding in findings:
        db_payload = finding.model_dump()
        assert "Secret" not in db_payload
        assert "secret" not in db_payload
        for value in db_payload.values():
            if isinstance(value, str):
                for secret_value in SECRET_VALUES:
                    assert secret_value not in value


def test_normalize_gitleaks_does_not_log_secret_values(capsys):
    fixture_path = Path(__file__).parent / "fixtures" / "sample_gitleaks.json"

    normalize_gitleaks(str(fixture_path), "scan_002")
    captured = capsys.readouterr()

    combined_output = captured.out + captured.err
    for secret_value in SECRET_VALUES:
        assert secret_value not in combined_output


def test_normalize_gitleaks_ignores_secret_text():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_gitleaks.json"

    findings = normalize_gitleaks(str(fixture_path), "scan_002")

    assert [finding.title for finding in findings] == [
        "Secret detected: generic-api-key",
        "Secret detected: private-key",
    ]
    assert all(finding.component is None for finding in findings)
    assert all(finding.cve is None for finding in findings)
    assert all(finding.cwe is None for finding in findings)
