from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy import event
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.findings.fingerprint import generate_finding_fingerprint


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)
    scanner: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    component: Mapped[str | None] = mapped_column(String, nullable=True)
    cve: Mapped[str | None] = mapped_column(String, nullable=True)
    cwe: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_json_path: Mapped[str | None] = mapped_column(String, nullable=True)
    llm_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False)


@event.listens_for(Finding, "before_insert")
@event.listens_for(Finding, "before_update")
def _set_finding_fingerprint(mapper, connection, target: Finding) -> None:
    target.fingerprint = generate_finding_fingerprint(target)
