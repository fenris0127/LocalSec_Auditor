from __future__ import annotations

import subprocess

from fastapi.testclient import TestClient

from app.main import app
from app.scanners.runner import CommandResult
from app.tools import trivy


def test_update_trivy_db_builds_expected_command_without_shell(monkeypatch):
    monkeypatch.setenv("LOCALSC_OFFLINE_MODE", "0")
    calls = []

    def fake_subprocess_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="DB downloaded\n",
            stderr="",
        )

    monkeypatch.setattr("app.scanners.runner.subprocess.run", fake_subprocess_run)

    result = trivy.update_trivy_db(timeout=123)

    assert result.success is True
    assert result.command == ["trivy", "image", "--download-db-only"]
    assert result.stdout == "DB downloaded\n"
    assert result.stderr == ""
    assert result.exit_code == 0
    assert calls == [
        (
            ["trivy", "image", "--download-db-only"],
            {
                "capture_output": True,
                "text": True,
                "timeout": 123,
            },
        )
    ]
    assert "shell" not in calls[0][1]


def test_update_trivy_db_is_blocked_in_offline_mode(monkeypatch):
    monkeypatch.setenv("LOCALSC_OFFLINE_MODE", "1")
    run_called = False

    def fake_run_command(command, timeout=None):
        nonlocal run_called
        run_called = True
        return CommandResult(stdout="", stderr="", exit_code=0)

    monkeypatch.setattr(trivy, "run_command", fake_run_command)

    try:
        trivy.update_trivy_db()
    except trivy.OfflineModeError as exc:
        assert "LOCALSC_OFFLINE_MODE" in str(exc)
    else:
        raise AssertionError("update_trivy_db should fail in offline mode")

    assert run_called is False


def test_update_trivy_db_api_runs_when_update_mode_enabled(monkeypatch):
    monkeypatch.setenv("LOCALSC_OFFLINE_MODE", "false")

    def fake_update_trivy_db():
        return trivy.TrivyDbUpdateResult(
            command=["trivy", "image", "--download-db-only"],
            success=True,
            stdout="DB downloaded\n",
            stderr="",
            exit_code=0,
            timed_out=False,
            error_message=None,
        )

    monkeypatch.setattr("app.api.tools.update_trivy_db", fake_update_trivy_db)
    client = TestClient(app)

    response = client.post("/api/tools/trivy/update-db")

    assert response.status_code == 200
    assert response.json() == {
        "command": ["trivy", "image", "--download-db-only"],
        "success": True,
        "stdout": "DB downloaded\n",
        "stderr": "",
        "exit_code": 0,
        "timed_out": False,
        "error_message": None,
    }


def test_update_trivy_db_api_blocks_offline_mode(monkeypatch):
    monkeypatch.setenv("LOCALSC_OFFLINE_MODE", "true")
    client = TestClient(app)

    response = client.post("/api/tools/trivy/update-db")

    assert response.status_code == 409
    assert "LOCALSC_OFFLINE_MODE" in response.json()["detail"]
