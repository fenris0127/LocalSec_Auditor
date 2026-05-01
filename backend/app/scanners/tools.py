from __future__ import annotations

from dataclasses import dataclass

from app.scanners.runner import run_command


TOOL_STATUS_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class ToolStatus:
    installed: bool
    version: str | None
    error: str | None


TOOL_VERSION_COMMANDS = {
    "semgrep": ["semgrep", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "trivy": ["trivy", "--version"],
}


def _version_text(stdout: str, stderr: str) -> str | None:
    text = (stdout or stderr).strip()
    if not text:
        return None
    return text.splitlines()[0].strip() or None


def check_tool_status(tool_name: str, timeout: int | float = TOOL_STATUS_TIMEOUT_SECONDS) -> ToolStatus:
    command = TOOL_VERSION_COMMANDS[tool_name]
    result = run_command(command, timeout=timeout)

    if result.exit_code == 0:
        return ToolStatus(
            installed=True,
            version=_version_text(result.stdout, result.stderr),
            error=None,
        )

    return ToolStatus(
        installed=False,
        version=None,
        error=result.error_message or result.stderr.strip() or f"{tool_name} version check failed",
    )


def get_tools_status() -> dict[str, ToolStatus]:
    return {tool_name: check_tool_status(tool_name) for tool_name in TOOL_VERSION_COMMANDS}
