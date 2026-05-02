from pathlib import Path

from app.normalizers.lynis import normalize_lynis


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_normalize_lynis_creates_config_findings_from_warnings_and_suggestions():
    fixture = FIXTURE_DIR / "sample_lynis.txt"

    findings = normalize_lynis(str(fixture), "scan_lynis")

    assert len(findings) == 4
    assert {finding.scanner for finding in findings} == {"lynis"}
    assert {finding.category for finding in findings} == {"config"}
    assert {finding.severity for finding in findings} == {"medium"}
    assert [finding.title for finding in findings] == [
        "SSH root login is permitted",
        "Configure a password aging policy",
        "Firewall is not enabled",
        "Install security updates automatically",
    ]
    assert {finding.rule_id for finding in findings} == {
        "lynis:warning",
        "lynis:suggestion",
    }
    assert all(finding.scan_id == "scan_lynis" for finding in findings)
    assert all(finding.raw_json_path == str(fixture) for finding in findings)


def test_normalize_lynis_returns_empty_when_no_warning_or_suggestion(tmp_path):
    raw_result = tmp_path / "lynis.txt"
    raw_result.write_text("Everything looks quiet\n[OK] boot services checked\n", encoding="utf-8")

    assert normalize_lynis(str(raw_result), "scan_empty") == []
