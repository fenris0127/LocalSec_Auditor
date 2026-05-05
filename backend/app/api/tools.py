from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.database import get_db_session
from app.scanners.tools import get_tools_status
from app.services.dashboard_summary import build_dashboard_summary


router = APIRouter(prefix="/api", tags=["tools"])


class ToolStatusResponse(BaseModel):
    installed: bool
    version: str | None
    error: str | None


@router.get("/tools/status", response_model=dict[str, ToolStatusResponse])
def tools_status_api() -> dict[str, ToolStatusResponse]:
    return get_tools_status()


@router.get("/dashboard/summary", tags=["dashboard"])
def get_dashboard_summary_api(db: Session = Depends(get_db_session)) -> dict:
    return build_dashboard_summary(db)
