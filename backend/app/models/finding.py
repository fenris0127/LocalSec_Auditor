from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)
    scanner: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    component: Mapped[str | None] = mapped_column(String, nullable=True)
    cve: Mapped[str | None] = mapped_column(String, nullable=True)
    cwe: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_json_path: Mapped[str | None] = mapped_column(String, nullable=True)
    llm_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False)
