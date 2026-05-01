from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.scanners.runner import CommandResult
from app.scanners.tools import check_tool_status


def test_check_tool_status_uses_expected_commands_without_shell():
    results = {
        ("semgrep", "--version"): CommandResult(stdout="1.2.3\n", stderr="", exit_code=0),
        ("gitleaks", "version"): CommandResult(stdout="8.0.0\n", stderr="", exit_code=0),
        ("trivy", "--version"): CommandResult(stdout="Version: 0.50.0\nVulnerability DB: 1", stderr="", exit_code=0),
    }

    def fake_run_command(command, timeout=None):
        return results[tuple(command)]

    with patch("app.scanners.tools.run_command", side_effect=fake_run_command) as run_command:
        assert check_tool_status("semgrep").version == "1.2.3"
        assert check_tool_status("gitleaks").version == "8.0.0"
        assert check_tool_status("trivy").version == "Version: 0.50.0"

    assert [call.args[0] for call in run_command.call_args_list] == [
        ["semgrep", "--version"],
        ["gitleaks", "version"],
        ["trivy", "--version"],
    ]
    assert all(call.kwargs["timeout"] == 5 for call in run_command.call_args_list)
    assert all("shell" not in call.kwargs for call in run_command.call_args_list)


def test_check_tool_status_returns_not_installed_for_missing_tool():
    with patch(
        "app.scanners.tools.run_command",
        return_value=CommandResult(stdout="", stderr="", exit_code=None, error_message="not found"),
    ):
        status = check_tool_status("semgrep")

    assert status.installed is False
    assert status.version is None
    assert status.error == "not found"


def test_tools_status_api_returns_status_for_all_tools_without_server_error():
    responses = {
        "semgrep": CommandResult(stdout="1.2.3\n", stderr="", exit_code=0),
        "gitleaks": CommandResult(stdout="", stderr="", exit_code=None, error_message="not found"),
        "trivy": CommandResult(stdout="", stderr="trivy failed", exit_code=1),
    }

    def fake_run_command(command, timeout=None):
        return responses[command[0]]

    client = TestClient(app)
    with patch("app.scanners.tools.run_command", side_effect=fake_run_command):
        response = client.get("/api/tools/status")

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "semgrep": {"installed": True, "version": "1.2.3", "error": None},
        "gitleaks": {"installed": False, "version": None, "error": "not found"},
        "trivy": {"installed": False, "version": None, "error": "trivy failed"},
    }
