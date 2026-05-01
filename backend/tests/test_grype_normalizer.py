from pathlib import Path

from app.normalizers.grype import normalize_grype


def test_normalize_grype_creates_cve_findings_from_sample_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_grype.json"

    findings = normalize_grype(str(fixture_path), "scan_004")

    assert len(findings) == 2
    assert findings[0].scan_id == "scan_004"
    assert findings[0].category == "cve"
    assert findings[0].scanner == "grype"
    assert findings[0].cve == "CVE-2026-3000"
    assert findings[0].component == "lodash"
    assert findings[0].installed_version == "4.17.20"
    assert findings[0].fixed_version == "4.17.21"
    assert findings[0].severity == "high"
    assert findings[0].title == "CVE-2026-3000 in lodash (fixed: 4.17.21)"
    assert findings[0].raw_json_path == str(fixture_path)
    assert findings[0].status == "open"


def test_normalize_grype_extracts_component_severity_and_fixed_versions():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_grype.json"

    findings = normalize_grype(str(fixture_path), "scan_004")

    assert [finding.cve for finding in findings] == [
        "CVE-2026-3000",
        "CVE-2026-4000",
    ]
    assert [finding.component for finding in findings] == ["lodash", "axios"]
    assert [finding.severity for finding in findings] == ["high", "medium"]
    assert [finding.fixed_version for finding in findings] == ["4.17.21", "1.6.8, 1.7.0"]
