from fastapi import APIRouter
from pydantic import BaseModel

from app.scanners.tools import get_tools_status


router = APIRouter(prefix="/api/tools", tags=["tools"])


class ToolStatusResponse(BaseModel):
    installed: bool
    version: str | None
    error: str | None


@router.get("/status", response_model=dict[str, ToolStatusResponse])
def tools_status_api() -> dict[str, ToolStatusResponse]:
    return get_tools_status()
