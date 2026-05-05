from pydantic import BaseModel, Field, field_validator


WORKFLOW_TASK_STATUSES = {
    "pending",
    "ready",
    "running",
    "completed",
    "failed",
    "skipped",
    "cancelled",
}


class WorkflowTaskCreate(BaseModel):
    id: str
    scan_id: str
    task_type: str
    tool_name: str | None = None
    status: str
    depends_on: list[str] = Field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 0
    error_message: str | None = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, status: str) -> str:
        if status not in WORKFLOW_TASK_STATUSES:
            raise ValueError(f"unsupported workflow task status: {status}")
        return status


class WorkflowTaskResponse(BaseModel):
    id: str
    scan_id: str
    task_type: str
    tool_name: str | None
    status: str
    depends_on: list[str]
    retry_count: int
    max_retries: int
    error_message: str | None
