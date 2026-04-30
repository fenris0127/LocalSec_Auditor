from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.base import Base


settings = get_settings()
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def ensure_db_parent_dir() -> None:
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)


def check_db_connection(db_engine: Engine | None = None) -> bool:
    if db_engine is None:
        ensure_db_parent_dir()
        db_engine = engine

    with db_engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return True


def create_db_tables(db_engine: Engine | None = None) -> None:
    if db_engine is None:
        ensure_db_parent_dir()
        db_engine = engine

    from app.models import Scan  # noqa: F401

    Base.metadata.create_all(bind=db_engine)


def get_db_session() -> Generator[Session, None, None]:
    ensure_db_parent_dir()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
