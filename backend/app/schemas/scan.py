from datetime import datetime

from pydantic import BaseModel


class ScanCreateRequest(BaseModel):
    project_name: str
    target_path: str
    scan_types: list[str]
    llm_enabled: bool = True


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: str


class ScanResponse(BaseModel):
    id: str
    project_name: str
    target_path: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanTaskResponse(BaseModel):
    id: str
    scan_id: str
    task_type: str
    tool_name: str | None
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None

    model_config = {"from_attributes": True}
