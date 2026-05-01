from app.services import scan_dirs
from app.services.scan_dirs import create_scan_dirs


def test_create_scan_dirs_makes_expected_folders(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_dirs, "PROJECT_ROOT", tmp_path)

    paths = create_scan_dirs("scan_123")

    assert paths["raw"] == tmp_path / "data" / "scans" / "scan_123" / "raw"
    assert paths["normalized"] == tmp_path / "data" / "scans" / "scan_123" / "normalized"
    assert paths["reports"] == tmp_path / "data" / "scans" / "scan_123" / "reports"
    assert paths["raw_syft_sbom"] == (
        tmp_path / "data" / "scans" / "scan_123" / "raw" / "syft-sbom.json"
    )
    assert paths["raw_grype"] == tmp_path / "data" / "scans" / "scan_123" / "raw" / "grype.json"
    assert paths["raw"].is_dir()
    assert paths["normalized"].is_dir()
    assert paths["reports"].is_dir()
    assert paths["raw_syft_sbom"].exists() is False
    assert paths["raw_grype"].exists() is False


def test_create_scan_dirs_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_dirs, "PROJECT_ROOT", tmp_path)

    first = create_scan_dirs("scan_123")
    second = create_scan_dirs("scan_123")

    assert first == second
    assert second["raw"].is_dir()
    assert second["normalized"].is_dir()
    assert second["reports"].is_dir()


def test_create_scan_dirs_returns_sbom_and_grype_raw_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_dirs, "PROJECT_ROOT", tmp_path)

    paths = create_scan_dirs("scan_abc")

    raw_dir = tmp_path / "data" / "scans" / "scan_abc" / "raw"
    assert paths["raw_syft_sbom"] == raw_dir / "syft-sbom.json"
    assert paths["raw_grype"] == raw_dir / "grype.json"
