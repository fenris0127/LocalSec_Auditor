from fastapi import APIRouter

from app.core.config import OFFLINE_MODE_ENV, get_settings


router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/offline-mode")
def get_offline_mode_api() -> dict[str, object]:
    settings = get_settings()
    return {
        "offline_mode": settings.offline_mode,
        "mode": "offline" if settings.offline_mode else "update",
        "updates_enabled": settings.updates_enabled,
        "env_var": OFFLINE_MODE_ENV,
    }
