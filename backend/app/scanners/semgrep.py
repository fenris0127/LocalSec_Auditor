from pathlib import Path

from app.scanners.runner import CommandResult, run_command


def run_semgrep(
    target_path: str,
    output_path: str,
    timeout: int | float | None = None,
) -> CommandResult:
    command = ["semgrep", "scan", "--config", "auto", target_path, "--json"]
    result = run_command(command, timeout=timeout)

    if result.stdout:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.stdout, encoding="utf-8")

    return result
