import os
from pathlib import Path

from app.core.config import SEMGREP_RULES_PATH_ENV, get_settings
from app.scanners.runner import CommandResult, run_command


def _resolve_rules_path(rules_path: str | None, use_local_rules: bool) -> Path | None:
    if rules_path is not None:
        return Path(rules_path).expanduser()

    settings = get_settings()
    if SEMGREP_RULES_PATH_ENV in os.environ:
        return settings.semgrep_rules_path
    if use_local_rules:
        return settings.semgrep_rules_path
    return None


def run_semgrep(
    target_path: str,
    output_path: str,
    timeout: int | float | None = None,
    rules_path: str | None = None,
    use_local_rules: bool = False,
) -> CommandResult:
    local_rules_path = _resolve_rules_path(rules_path, use_local_rules)
    if local_rules_path is None:
        config = "auto"
    else:
        if not local_rules_path.is_dir():
            return CommandResult(
                stdout="",
                stderr="",
                exit_code=None,
                error_message=f"Semgrep rules path not found: {local_rules_path}",
            )
        config = str(local_rules_path)

    command = ["semgrep", "scan", "--config", config, target_path, "--json"]
    result = run_command(command, timeout=timeout)

    if result.stdout:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.stdout, encoding="utf-8")

    return result
