import subprocess
from unittest.mock import Mock, patch

from app.scanners.runner import CommandResult, run_command


def test_run_command_uses_list_args_without_shell_true():
    completed = subprocess.CompletedProcess(
        args=["tool", "--json"],
        returncode=0,
        stdout="ok",
        stderr="",
    )

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_command(["tool", "--json"], timeout=30)

    run.assert_called_once_with(
        ["tool", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "shell" not in run.call_args.kwargs
    assert result == CommandResult(stdout="ok", stderr="", exit_code=0)


def test_run_command_stores_exit_code_stdout_and_stderr():
    completed = subprocess.CompletedProcess(
        args=["tool"],
        returncode=2,
        stdout="partial output",
        stderr="scanner failed",
    )

    with patch("app.scanners.runner.subprocess.run", return_value=completed):
        result = run_command(["tool"])

    assert result.exit_code == 2
    assert result.stdout == "partial output"
    assert result.stderr == "scanner failed"
    assert result.timed_out is False
    assert result.error_message is None


def test_run_command_timeout_returns_result_object():
    timeout_error = subprocess.TimeoutExpired(
        cmd=["tool"],
        timeout=1,
        output="started",
        stderr="still running",
    )

    with patch("app.scanners.runner.subprocess.run", side_effect=timeout_error):
        result = run_command(["tool"], timeout=1)

    assert result.exit_code is None
    assert result.stdout == "started"
    assert result.stderr == "still running"
    assert result.timed_out is True
    assert result.error_message == "Command timed out"


def test_run_command_os_error_returns_result_object():
    with patch("app.scanners.runner.subprocess.run", side_effect=FileNotFoundError("missing")):
        result = run_command(["missing-tool"])

    assert result.exit_code is None
    assert result.stdout == ""
    assert result.stderr == ""
    assert result.timed_out is False
    assert "missing" in result.error_message


def test_run_command_empty_command_returns_result_without_running():
    run = Mock()

    with patch("app.scanners.runner.subprocess.run", run):
        result = run_command([])

    run.assert_not_called()
    assert result.exit_code is None
    assert result.error_message == "Command must not be empty"
