import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "localsec.db"
DB_PATH_ENV = "LOCALSEC_DB_PATH"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_BASE_URL_ENV = "OLLAMA_BASE_URL"
DEFAULT_OLLAMA_MODEL = "localsec-security"
OLLAMA_MODEL_ENV = "OLLAMA_MODEL"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 30.0
DEFAULT_WORKSPACE_ROOT = Path("C:/AI/projects")
WORKSPACE_ROOT_ENV = "LOCALSC_WORKSPACE"


@dataclass(frozen=True)
class Settings:
    database_path: Path
    workspace_root: Path = DEFAULT_WORKSPACE_ROOT

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.database_path.as_posix()}"


@dataclass(frozen=True)
class OllamaSettings:
    base_url: str
    model: str
    timeout_seconds: float


def get_settings() -> Settings:
    db_path = Path(os.getenv(DB_PATH_ENV, str(DEFAULT_DB_PATH))).expanduser()
    workspace_root = Path(os.getenv(WORKSPACE_ROOT_ENV, str(DEFAULT_WORKSPACE_ROOT))).expanduser()
    return Settings(database_path=db_path, workspace_root=workspace_root)


def get_ollama_settings() -> OllamaSettings:
    return OllamaSettings(
        base_url=os.getenv(OLLAMA_BASE_URL_ENV, DEFAULT_OLLAMA_BASE_URL),
        model=os.getenv(OLLAMA_MODEL_ENV, DEFAULT_OLLAMA_MODEL),
        timeout_seconds=DEFAULT_OLLAMA_TIMEOUT_SECONDS,
    )
