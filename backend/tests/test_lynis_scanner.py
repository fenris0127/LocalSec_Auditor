import subprocess
from unittest.mock import patch

from app.scanners.lynis import run_lynis_audit


def test_run_lynis_audit_builds_expected_readonly_command(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="Lynis audit output",
        stderr="",
    )
    output_path = tmp_path / "lynis.txt"

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_lynis_audit(str(output_path), timeout=60)

    run.assert_called_once_with(
        ["lynis", "audit", "system", "--no-colors"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert "shell" not in run.call_args.kwargs
    assert result.exit_code == 0


def test_run_lynis_audit_saves_stdout_to_output_path(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="Readonly audit result",
        stderr="",
    )
    output_path = tmp_path / "raw" / "lynis.txt"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_lynis_audit(str(output_path))

    assert result.exit_code == 0
    assert output_path.read_text(encoding="utf-8") == "Readonly audit result"


def test_run_lynis_audit_records_failure_without_raising(tmp_path):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="lynis failed",
    )
    output_path = tmp_path / "lynis.txt"

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_lynis_audit(str(output_path))

    assert result.exit_code == 1
    assert result.stderr == "lynis failed"
    assert output_path.exists() is False
