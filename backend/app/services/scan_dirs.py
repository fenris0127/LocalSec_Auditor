from pathlib import Path

from app.core.config import PROJECT_ROOT


def create_scan_dirs(scan_id: str) -> dict[str, Path]:
    scan_root = PROJECT_ROOT / "data" / "scans" / scan_id
    paths = {
        "raw": scan_root / "raw",
        "normalized": scan_root / "normalized",
        "reports": scan_root / "reports",
    }

    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)

    return paths
