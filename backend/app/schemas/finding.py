from pydantic import BaseModel


class FindingCreate(BaseModel):
    id: str
    scan_id: str
    category: str
    scanner: str
    severity: str
    title: str
    rule_id: str | None = None
    file_path: str | None = None
    line: int | None = None
    component: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    cve: str | None = None
    cwe: str | None = None
    cce_id: str | None = None
    current_value: str | None = None
    expected_value: str | None = None
    raw_json_path: str | None = None
    llm_summary: str | None = None
    status: str = "open"


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    category: str
    scanner: str
    severity: str
    title: str
    rule_id: str | None = None
    file_path: str | None = None
    line: int | None = None
    component: str | None = None
    cve: str | None = None
    cwe: str | None = None
    cce_id: str | None = None
    current_value: str | None = None
    expected_value: str | None = None
    raw_json_path: str | None = None
    llm_summary: str | None = None
    status: str

    model_config = {"from_attributes": True}
