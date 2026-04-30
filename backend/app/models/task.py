from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    task_type: Mapped[str] = mapped_column(String, nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[str | None] = mapped_column(String, nullable=True)
