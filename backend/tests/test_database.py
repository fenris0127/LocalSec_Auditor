from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import DB_PATH_ENV, DEFAULT_DB_PATH, Settings, get_settings
from app.db import database


def test_default_db_path_points_to_data_dir(monkeypatch):
    monkeypatch.delenv(DB_PATH_ENV, raising=False)

    settings = get_settings()

    assert settings.database_path == DEFAULT_DB_PATH
    assert settings.database_path.name == "localsec.db"
    assert settings.database_path.parent.name == "data"


def test_env_can_override_db_path(monkeypatch, tmp_path):
    db_path = tmp_path / "custom.db"
    monkeypatch.setenv(DB_PATH_ENV, str(db_path))

    settings = get_settings()

    assert settings.database_path == db_path
    assert settings.database_url == f"sqlite:///{db_path.as_posix()}"


def test_check_db_connection_creates_sqlite_file(tmp_path):
    db_path = tmp_path / "localsec.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")

    assert database.check_db_connection(engine) is True
    assert db_path.exists()


def test_get_db_session_returns_session(monkeypatch, tmp_path):
    db_path = tmp_path / "session.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(database, "settings", Settings(database_path=db_path))
    monkeypatch.setattr(database, "SessionLocal", session_local)

    session = next(database.get_db_session())
    try:
        assert isinstance(session, Session)
    finally:
        session.close()
