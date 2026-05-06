from __future__ import annotations

from dataclasses import dataclass

from app.core.config import get_settings
from app.scanners.runner import CommandResult, run_command


GRYPE_DB_UPDATE_COMMAND = ["grype", "db", "update"]
DEFAULT_GRYPE_DB_UPDATE_TIMEOUT_SECONDS = 600


class OfflineModeError(RuntimeError):
    pass


@dataclass(frozen=True)
class GrypeDbUpdateResult:
    command: list[str]
    success: bool
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    error_message: str | None


def _to_update_result(command: list[str], result: CommandResult) -> GrypeDbUpdateResult:
    return GrypeDbUpdateResult(
        command=command,
        success=result.exit_code == 0,
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        error_message=result.error_message,
    )


def update_grype_db(timeout: int | float = DEFAULT_GRYPE_DB_UPDATE_TIMEOUT_SECONDS) -> GrypeDbUpdateResult:
    settings = get_settings()
    if settings.offline_mode:
        raise OfflineModeError("Grype DB update is disabled while LOCALSC_OFFLINE_MODE is enabled")

    command = list(GRYPE_DB_UPDATE_COMMAND)
    result = run_command(command, timeout=timeout)
    return _to_update_result(command, result)
