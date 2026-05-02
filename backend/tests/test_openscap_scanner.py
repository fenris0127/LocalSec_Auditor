import subprocess
from unittest.mock import patch

from app.scanners.openscap import run_openscap


def test_run_openscap_builds_expected_readonly_command_for_xml(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="",
        stderr="",
    )
    output_path = tmp_path / "openscap.xml"
    scap_content_path = "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_openscap(
            "xccdf_org.ssgproject.content_profile_cis_level1_server",
            str(output_path),
            timeout=90,
            scap_content_path=scap_content_path,
        )

    run.assert_called_once_with(
        [
            "oscap",
            "xccdf",
            "eval",
            "--profile",
            "xccdf_org.ssgproject.content_profile_cis_level1_server",
            "--results",
            str(output_path),
            scap_content_path,
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    command = run.call_args.args[0]
    assert "remediate" not in command
    assert "--remediate" not in command
    assert "shell" not in run.call_args.kwargs
    assert result.exit_code == 0


def test_run_openscap_supports_json_output_path_without_remediation(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="",
        stderr="",
    )
    output_path = tmp_path / "raw" / "openscap.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_openscap(
            "xccdf_org.ssgproject.content_profile_standard",
            str(output_path),
            scap_content_path="C:/scap/content.xml",
        )

    command = run.call_args.args[0]
    assert command == [
        "oscap",
        "xccdf",
        "eval",
        "--profile",
        "xccdf_org.ssgproject.content_profile_standard",
        "--results",
        str(output_path),
        "C:/scap/content.xml",
    ]
    assert output_path.parent.is_dir()
    assert "remediate" not in command
    assert "--remediate" not in command
    assert result.exit_code == 0


def test_run_openscap_records_failure_without_raising(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=2,
        stdout="",
        stderr="openscap failed",
    )
    output_path = tmp_path / "openscap.xml"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_openscap(
            "xccdf_org.ssgproject.content_profile_standard",
            str(output_path),
            scap_content_path="C:/scap/content.xml",
        )

    assert result.exit_code == 2
    assert result.stderr == "openscap failed"
