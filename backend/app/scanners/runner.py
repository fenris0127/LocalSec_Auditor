from dataclasses import dataclass
import subprocess


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool = False
    error_message: str | None = None


def run_command(command: list[str], timeout: int | float | None = None) -> CommandResult:
    if not command:
        return CommandResult(
            stdout="",
            stderr="",
            exit_code=None,
            error_message="Command must not be empty",
        )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            exit_code=None,
            timed_out=True,
            error_message="Command timed out",
        )
    except OSError as exc:
        return CommandResult(
            stdout="",
            stderr="",
            exit_code=None,
            error_message=str(exc),
        )

    return CommandResult(
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
    )
