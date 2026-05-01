import subprocess
from unittest.mock import patch

from app.scanners.grype import run_grype_sbom


def test_run_grype_sbom_builds_expected_command_with_sbom_path(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='{"matches":[]}',
        stderr="",
    )
    sbom_path = tmp_path / "syft.json"
    output_path = tmp_path / "grype.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_grype_sbom(str(sbom_path), str(output_path), timeout=30)

    run.assert_called_once_with(
        ["grype", f"sbom:{sbom_path}", "-o", "json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "shell" not in run.call_args.kwargs
    assert result.exit_code == 0


def test_run_grype_sbom_saves_stdout_to_output_path(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='{"matches":[{"vulnerability":{"id":"CVE-2026-0001"}}]}',
        stderr="",
    )
    sbom_path = tmp_path / "syft.json"
    output_path = tmp_path / "raw" / "grype.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_grype_sbom(str(sbom_path), str(output_path))

    assert result.exit_code == 0
    assert output_path.read_text(encoding="utf-8") == (
        '{"matches":[{"vulnerability":{"id":"CVE-2026-0001"}}]}'
    )


def test_run_grype_sbom_records_failure_stderr_and_exit_code(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="grype failed",
    )
    sbom_path = tmp_path / "syft.json"
    output_path = tmp_path / "grype.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_grype_sbom(str(sbom_path), str(output_path))

    assert result.exit_code == 1
    assert result.stderr == "grype failed"
    assert output_path.exists() is False
