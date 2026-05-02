from pathlib import Path

from app.normalizers.openscap import normalize_openscap


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_normalize_openscap_creates_cce_findings_from_failed_rules():
    fixture = FIXTURE_DIR / "sample_openscap.xml"

    findings = normalize_openscap(str(fixture), "scan_openscap")

    assert len(findings) == 2
    assert {finding.category for finding in findings} == {"cce"}
    assert {finding.scanner for finding in findings} == {"openscap"}
    assert [finding.rule_id for finding in findings] == [
        "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
        "xccdf_org.ssgproject.content_rule_partition_for_tmp",
    ]
    assert [finding.title for finding in findings] == [
        "Disable SSH root login",
        "Create separate partition for /tmp",
    ]
    assert [finding.severity for finding in findings] == ["high", "medium"]
    assert findings[0].cce_id == "CCE-80801-6"
    assert findings[1].cce_id is None
    assert all(finding.scan_id == "scan_openscap" for finding in findings)
    assert all(finding.raw_json_path == str(fixture) for finding in findings)


def test_normalize_openscap_ignores_passed_rules(tmp_path):
    raw_result = tmp_path / "openscap.xml"
    raw_result.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <Rule id="xccdf_org.example_rule_passed" severity="high">
    <title>Already compliant</title>
  </Rule>
  <TestResult id="sample">
    <rule-result idref="xccdf_org.example_rule_passed">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>
""",
        encoding="utf-8",
    )

    assert normalize_openscap(str(raw_result), "scan_clean") == []
