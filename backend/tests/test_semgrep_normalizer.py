from pathlib import Path

from app.normalizers.semgrep import normalize_semgrep


def test_normalize_semgrep_creates_findings_from_sample_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_semgrep.json"

    findings = normalize_semgrep(str(fixture_path), "scan_001")

    assert len(findings) == 4
    assert findings[0].scan_id == "scan_001"
    assert findings[0].category == "sast"
    assert findings[0].scanner == "semgrep"
    assert findings[0].file_path == "src/app.py"
    assert findings[0].line == 42
    assert findings[0].title == "Possible SQL injection"
    assert findings[0].raw_json_path == str(fixture_path)
    assert findings[0].status == "open"


def test_normalize_semgrep_maps_severity_levels():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_semgrep.json"

    findings = normalize_semgrep(str(fixture_path), "scan_001")

    assert [finding.severity for finding in findings] == [
        "high",
        "medium",
        "low",
        "medium",
    ]
