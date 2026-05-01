from __future__ import annotations

from pathlib import Path

from app.core.config import get_settings


def _normalize_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def get_workspace_root() -> Path:
    return _normalize_path(get_settings().workspace_root)


def is_path_inside_workspace(target_path: str) -> bool:
    target = Path(target_path)
    if not target.is_absolute():
        return False

    workspace_root = get_workspace_root()
    normalized_target = _normalize_path(target)

    return normalized_target == workspace_root or normalized_target.is_relative_to(workspace_root)
