import subprocess
from unittest.mock import patch

from app.scanners.trivy import run_trivy_fs


def test_run_trivy_fs_builds_expected_command(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="",
        stderr="",
    )
    output_path = tmp_path / "trivy.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_trivy_fs("C:/AI/projects/demo", str(output_path), timeout=30)

    run.assert_called_once_with(
        [
            "trivy",
            "fs",
            "C:/AI/projects/demo",
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "shell" not in run.call_args.kwargs
    assert result.exit_code == 0


def test_run_trivy_fs_records_failure_stderr_and_exit_code(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="trivy failed",
    )
    output_path = tmp_path / "trivy.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_trivy_fs("C:/AI/projects/demo", str(output_path))

    assert result.exit_code == 1
    assert result.stderr == "trivy failed"
