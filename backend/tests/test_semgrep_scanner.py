import subprocess
from unittest.mock import patch

from app.scanners.semgrep import run_semgrep


def test_run_semgrep_builds_expected_command(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='{"results":[]}',
        stderr="",
    )
    output_path = tmp_path / "semgrep.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_semgrep("C:/AI/projects/demo", str(output_path), timeout=30)

    run.assert_called_once_with(
        ["semgrep", "scan", "--config", "auto", "C:/AI/projects/demo", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "shell" not in run.call_args.kwargs
    assert result.exit_code == 0


def test_run_semgrep_saves_stdout_to_output_path(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='{"results":[{"check_id":"demo"}]}',
        stderr="",
    )
    output_path = tmp_path / "raw" / "semgrep.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_semgrep("C:/AI/projects/demo", str(output_path))

    assert result.exit_code == 0
    assert output_path.read_text(encoding="utf-8") == '{"results":[{"check_id":"demo"}]}'


def test_run_semgrep_records_failure_without_raising(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=2,
        stdout="",
        stderr="semgrep failed",
    )
    output_path = tmp_path / "semgrep.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_semgrep("C:/AI/projects/demo", str(output_path))

    assert result.exit_code == 2
    assert result.stderr == "semgrep failed"
    assert output_path.exists() is False
