from pathlib import Path

from app.core.config import PROJECT_ROOT


def create_scan_dirs(scan_id: str) -> dict[str, Path]:
    scan_root = PROJECT_ROOT / "data" / "scans" / scan_id
    paths = {
        "raw": scan_root / "raw",
        "normalized": scan_root / "normalized",
        "reports": scan_root / "reports",
        "raw_syft_sbom": scan_root / "raw" / "syft-sbom.json",
        "raw_grype": scan_root / "raw" / "grype.json",
    }

    for path in (paths["raw"], paths["normalized"], paths["reports"]):
        path.mkdir(parents=True, exist_ok=True)

    return paths
