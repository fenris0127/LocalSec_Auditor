from fastapi.testclient import TestClient

from app.core.config import OFFLINE_MODE_ENV, get_settings
from app.main import app


def test_offline_mode_defaults_to_enabled(monkeypatch):
    monkeypatch.delenv(OFFLINE_MODE_ENV, raising=False)

    settings = get_settings()

    assert settings.offline_mode is True
    assert settings.updates_enabled is False


def test_offline_mode_can_be_disabled_by_env(monkeypatch):
    monkeypatch.setenv(OFFLINE_MODE_ENV, "false")

    settings = get_settings()

    assert settings.offline_mode is False
    assert settings.updates_enabled is True


def test_offline_mode_api_returns_current_mode(monkeypatch):
    monkeypatch.setenv(OFFLINE_MODE_ENV, "1")
    client = TestClient(app)

    response = client.get("/api/settings/offline-mode")

    assert response.status_code == 200
    assert response.json() == {
        "offline_mode": True,
        "mode": "offline",
        "updates_enabled": False,
        "env_var": "LOCALSC_OFFLINE_MODE",
    }


def test_offline_mode_api_returns_update_mode(monkeypatch):
    monkeypatch.setenv(OFFLINE_MODE_ENV, "0")
    client = TestClient(app)

    response = client.get("/api/settings/offline-mode")

    assert response.status_code == 200
    assert response.json() == {
        "offline_mode": False,
        "mode": "update",
        "updates_enabled": True,
        "env_var": "LOCALSC_OFFLINE_MODE",
    }
