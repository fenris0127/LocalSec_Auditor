from datetime import datetime

from pydantic import BaseModel


class ProjectCreate(BaseModel):
    id: str
    name: str
    root_path: str


class ProjectUpdate(BaseModel):
    name: str | None = None
    root_path: str | None = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    root_path: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
