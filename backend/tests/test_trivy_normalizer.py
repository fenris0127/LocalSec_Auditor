from pathlib import Path

from app.normalizers.trivy import normalize_trivy


def test_normalize_trivy_creates_cve_findings_from_sample_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_trivy.json"

    findings = normalize_trivy(str(fixture_path), "scan_003")

    assert len(findings) == 2
    assert findings[0].scan_id == "scan_003"
    assert findings[0].category == "cve"
    assert findings[0].scanner == "trivy"
    assert findings[0].cve == "CVE-2026-1000"
    assert findings[0].component == "lodash"
    assert findings[0].installed_version == "4.17.20"
    assert findings[0].fixed_version == "4.17.21"
    assert findings[0].severity == "high"
    assert findings[0].title == "Prototype Pollution in lodash (fixed: 4.17.21)"
    assert findings[0].raw_json_path == str(fixture_path)
    assert findings[0].status == "open"


def test_normalize_trivy_extracts_component_and_severity():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_trivy.json"

    findings = normalize_trivy(str(fixture_path), "scan_003")

    assert [finding.cve for finding in findings] == [
        "CVE-2026-1000",
        "CVE-2026-2000",
    ]
    assert [finding.component for finding in findings] == ["lodash", "axios"]
    assert [finding.severity for finding in findings] == ["high", "medium"]
