from __future__ import annotations

import os
from pathlib import Path

from app.scanners.runner import CommandResult, run_command


DEFAULT_SCAP_CONTENT_PATH_ENV = "LOCALSEC_SCAP_CONTENT_PATH"
DEFAULT_SCAP_CONTENT_PATH = "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"


def _result_flag(output_path: str) -> str:
    suffix = Path(output_path).suffix.lower()
    if suffix == ".json":
        return "--results"
    return "--results"


def run_openscap(
    profile: str,
    output_path: str,
    timeout: int | float | None = None,
    scap_content_path: str | None = None,
) -> CommandResult:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    content_path = scap_content_path or os.getenv(
        DEFAULT_SCAP_CONTENT_PATH_ENV,
        DEFAULT_SCAP_CONTENT_PATH,
    )
    command = [
        "oscap",
        "xccdf",
        "eval",
        "--profile",
        profile,
        _result_flag(output_path),
        str(output),
        content_path,
    ]
    return run_command(command, timeout=timeout)
