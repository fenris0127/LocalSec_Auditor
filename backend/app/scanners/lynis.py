from pathlib import Path

from app.scanners.runner import CommandResult, run_command


def run_lynis_audit(
    output_path: str,
    timeout: int | float | None = None,
) -> CommandResult:
    command = ["lynis", "audit", "system", "--no-colors"]
    result = run_command(command, timeout=timeout)

    if result.stdout:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.stdout, encoding="utf-8")

    return result
