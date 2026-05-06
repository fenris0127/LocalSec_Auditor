from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.database import get_db_session
from app.scanners.tools import get_tools_status
from app.services.dashboard_summary import build_dashboard_summary
from app.tools.trivy import OfflineModeError, update_trivy_db


router = APIRouter(prefix="/api", tags=["tools"])


class ToolStatusResponse(BaseModel):
    installed: bool
    version: str | None
    error: str | None


class ToolUpdateResponse(BaseModel):
    command: list[str]
    success: bool
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    error_message: str | None


@router.get("/tools/status", response_model=dict[str, ToolStatusResponse])
def tools_status_api() -> dict[str, ToolStatusResponse]:
    return get_tools_status()


@router.post("/tools/trivy/update-db", response_model=ToolUpdateResponse)
def update_trivy_db_api() -> ToolUpdateResponse:
    try:
        return update_trivy_db()
    except OfflineModeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/dashboard/summary", tags=["dashboard"])
def get_dashboard_summary_api(db: Session = Depends(get_db_session)) -> dict:
    return build_dashboard_summary(db)
