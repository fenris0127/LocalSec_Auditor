from app.scanners.runner import CommandResult, run_command


def run_trivy_fs(
    target_path: str,
    output_path: str,
    timeout: int | float | None = None,
) -> CommandResult:
    command = [
        "trivy",
        "fs",
        target_path,
        "--format",
        "json",
        "--output",
        output_path,
    ]
    return run_command(command, timeout=timeout)
