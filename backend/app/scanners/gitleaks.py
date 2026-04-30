from app.scanners.runner import CommandResult, run_command


def run_gitleaks(
    target_path: str,
    output_path: str,
    timeout: int | float | None = None,
) -> CommandResult:
    command = [
        "gitleaks",
        "detect",
        "--source",
        target_path,
        "--report-format",
        "json",
        "--report-path",
        output_path,
    ]
    return run_command(command, timeout=timeout)
