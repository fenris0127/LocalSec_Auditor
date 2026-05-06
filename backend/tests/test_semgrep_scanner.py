import subprocess
from unittest.mock import patch

from app.core.config import DEFAULT_SEMGREP_RULES_PATH, SEMGREP_RULES_PATH_ENV
from app.scanners.semgrep import run_semgrep


def test_run_semgrep_builds_expected_command(tmp_path, monkeypatch):
    monkeypatch.delenv(SEMGREP_RULES_PATH_ENV, raising=False)
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


def test_run_semgrep_uses_explicit_local_rules_path(tmp_path, monkeypatch):
    monkeypatch.delenv(SEMGREP_RULES_PATH_ENV, raising=False)
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='{"results":[]}',
        stderr="",
    )
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    output_path = tmp_path / "semgrep.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_semgrep(
            "C:/AI/projects/demo",
            str(output_path),
            timeout=30,
            rules_path=str(rules_path),
        )

    run.assert_called_once_with(
        ["semgrep", "scan", "--config", str(rules_path), "C:/AI/projects/demo", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "shell" not in run.call_args.kwargs
    assert result.exit_code == 0


def test_run_semgrep_uses_env_local_rules_path(tmp_path, monkeypatch):
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='{"results":[]}',
        stderr="",
    )
    rules_path = tmp_path / "env-rules"
    rules_path.mkdir()
    output_path = tmp_path / "semgrep.json"
    monkeypatch.setenv(SEMGREP_RULES_PATH_ENV, str(rules_path))

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_semgrep("C:/AI/projects/demo", str(output_path), timeout=30)

    run.assert_called_once_with(
        ["semgrep", "scan", "--config", str(rules_path), "C:/AI/projects/demo", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.exit_code == 0


def test_run_semgrep_uses_default_local_rules_path_when_requested(tmp_path, monkeypatch):
    monkeypatch.delenv(SEMGREP_RULES_PATH_ENV, raising=False)
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='{"results":[]}',
        stderr="",
    )
    output_path = tmp_path / "semgrep.json"

    with patch("app.scanners.runner.subprocess.run", return_value=completed) as run:
        result = run_semgrep(
            "C:/AI/projects/demo",
            str(output_path),
            timeout=30,
            use_local_rules=True,
        )

    run.assert_called_once_with(
        [
            "semgrep",
            "scan",
            "--config",
            str(DEFAULT_SEMGREP_RULES_PATH),
            "C:/AI/projects/demo",
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.exit_code == 0


def test_run_semgrep_returns_clear_error_when_rules_path_is_missing(tmp_path, monkeypatch):
    monkeypatch.delenv(SEMGREP_RULES_PATH_ENV, raising=False)
    output_path = tmp_path / "semgrep.json"
    missing_rules_path = tmp_path / "missing-rules"

    with patch("app.scanners.runner.subprocess.run") as run:
        result = run_semgrep(
            "C:/AI/projects/demo",
            str(output_path),
            rules_path=str(missing_rules_path),
        )

    run.assert_not_called()
    assert result.exit_code is None
    assert result.error_message == f"Semgrep rules path not found: {missing_rules_path}"
    assert output_path.exists() is False


def test_run_semgrep_saves_stdout_to_output_path(tmp_path, monkeypatch):
    monkeypatch.delenv(SEMGREP_RULES_PATH_ENV, raising=False)
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


def test_run_semgrep_records_failure_without_raising(tmp_path, monkeypatch):
    monkeypatch.delenv(SEMGREP_RULES_PATH_ENV, raising=False)
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
