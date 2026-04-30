import subprocess
from unittest.mock import patch

from app.scanners.gitleaks import run_gitleaks


def test_run_gitleaks_builds_expected_command(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="",
        stderr="",
    )
    output_path = tmp_path / "gitleaks.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_gitleaks("C:/AI/projects/demo", str(output_path), timeout=30)

    run.assert_called_once_with(
        [
            "gitleaks",
            "detect",
            "--source",
            "C:/AI/projects/demo",
            "--report-format",
            "json",
            "--report-path",
            str(output_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "shell" not in run.call_args.kwargs
    assert result.exit_code == 0


def test_run_gitleaks_records_failure_stderr_and_exit_code(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="gitleaks failed",
    )
    output_path = tmp_path / "gitleaks.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_gitleaks("C:/AI/projects/demo", str(output_path))

    assert result.exit_code == 1
    assert result.stderr == "gitleaks failed"


def test_run_gitleaks_does_not_print_scanner_output(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="fake-secret-value",
    )
    output_path = tmp_path / "gitleaks.json"

    with (
        patch("app.scanners.runner.subprocess.run", return_value=completed),
        patch("builtins.print") as print_mock,
    ):
        result = run_gitleaks("C:/AI/projects/demo", str(output_path))

    print_mock.assert_not_called()
    assert result.stderr == "fake-secret-value"
