from datetime import datetime

from pydantic import BaseModel, field_validator

from app.schemas.finding import FindingResponse


ALLOWED_SCAN_TYPES = {
    "semgrep",
    "gitleaks",
    "trivy",
    "syft",
    "grype",
    "lynis",
    "openscap",
}


class ScanCreateRequest(BaseModel):
    project_name: str
    target_path: str
    scan_types: list[str]
    llm_enabled: bool = True
    run_immediately: bool = False

    @field_validator("scan_types")
    @classmethod
    def validate_scan_types(cls, scan_types: list[str]) -> list[str]:
        invalid_scan_types = sorted(set(scan_types) - ALLOWED_SCAN_TYPES)
        if invalid_scan_types:
            raise ValueError(f"unsupported scan_types: {', '.join(invalid_scan_types)}")
        return scan_types


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: str


class ScanResponse(BaseModel):
    id: str
    project_id: str | None = None
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


class FindingComparisonSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]


class ScanComparisonSummary(BaseModel):
    new_findings: FindingComparisonSummary
    resolved_findings: FindingComparisonSummary
    persistent_findings: FindingComparisonSummary


class ScanComparisonResponse(BaseModel):
    base_scan_id: str
    target_scan_id: str
    new_findings: list[FindingResponse]
    resolved_findings: list[FindingResponse]
    persistent_findings: list[FindingResponse]
    summary: ScanComparisonSummary
