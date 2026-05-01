import subprocess
from unittest.mock import patch

from app.scanners.syft import run_syft


def test_run_syft_builds_expected_command(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='{"artifacts":[]}',
        stderr="",
    )
    output_path = tmp_path / "syft.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_syft("C:/AI/projects/demo", str(output_path), timeout=30)

    run.assert_called_once_with(
        ["syft", "C:/AI/projects/demo", "-o", "json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "shell" not in run.call_args.kwargs
    assert result.exit_code == 0


def test_run_syft_saves_stdout_to_output_path(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='{"artifacts":[{"name":"demo"}]}',
        stderr="",
    )
    output_path = tmp_path / "raw" / "syft.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_syft("C:/AI/projects/demo", str(output_path))

    assert result.exit_code == 0
    assert output_path.read_text(encoding="utf-8") == '{"artifacts":[{"name":"demo"}]}'


def test_run_syft_records_failure_without_raising(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="syft failed",
    )
    output_path = tmp_path / "syft.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_syft("C:/AI/projects/demo", str(output_path))

    assert result.exit_code == 1
    assert result.stderr == "syft failed"
    assert output_path.exists() is False
