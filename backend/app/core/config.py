import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "localsec.db"
DB_PATH_ENV = "LOCALSEC_DB_PATH"


@dataclass(frozen=True)
class Settings:
    database_path: Path

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.database_path.as_posix()}"


def get_settings() -> Settings:
    db_path = Path(os.getenv(DB_PATH_ENV, str(DEFAULT_DB_PATH))).expanduser()
    return Settings(database_path=db_path)
