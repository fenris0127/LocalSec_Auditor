from app.services import scan_dirs
from app.services.scan_dirs import create_scan_dirs


def test_create_scan_dirs_makes_expected_folders(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_dirs, "PROJECT_ROOT", tmp_path)

    paths = create_scan_dirs("scan_123")

    assert paths["raw"] == tmp_path / "data" / "scans" / "scan_123" / "raw"
    assert paths["normalized"] == tmp_path / "data" / "scans" / "scan_123" / "normalized"
    assert paths["reports"] == tmp_path / "data" / "scans" / "scan_123" / "reports"
    assert paths["raw"].is_dir()
    assert paths["normalized"].is_dir()
    assert paths["reports"].is_dir()


def test_create_scan_dirs_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_dirs, "PROJECT_ROOT", tmp_path)

    first = create_scan_dirs("scan_123")
    second = create_scan_dirs("scan_123")

    assert first == second
    assert all(path.is_dir() for path in second.values())
