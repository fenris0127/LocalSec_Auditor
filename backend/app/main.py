from fastapi import FastAPI

from app.api.findings import router as findings_router
from app.api.scans import router as scans_router
from app.api.tools import router as tools_router
from app.db.database import create_db_tables


app = FastAPI(title="LocalSec Auditor API")
app.include_router(findings_router)
app.include_router(scans_router)
app.include_router(tools_router)


@app.on_event("startup")
def on_startup() -> None:
    create_db_tables()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
