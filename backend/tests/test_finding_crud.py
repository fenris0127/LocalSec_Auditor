from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.finding import (
    create_finding,
    get_finding,
    list_findings_by_scan,
    update_finding_llm_summary,
)
from app.crud.scan import create_scan
from app.db.base import Base
from app.models.finding import Finding


def make_session(tmp_path):
    db_path = tmp_path / "findings.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def test_create_multiple_findings_for_scan(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan(
            db,
            scan_id="scan_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="created",
            created_at=datetime(2026, 4, 30, 10, 0, 0),
        )
        first = create_finding(
            db,
            finding_id="finding_001",
            scan_id="scan_001",
            category="sast",
            scanner="semgrep",
            severity="high",
            title="Potential SQL injection",
            status="open",
            file_path="src/user.py",
            line=42,
            cwe="CWE-89",
            raw_json_path="data/scans/scan_001/raw/semgrep.json",
        )
        second = create_finding(
            db,
            finding_id="finding_002",
            scan_id="scan_001",
            category="cve",
            scanner="trivy",
            severity="medium",
            title="Vulnerable dependency",
            status="open",
            component="demo-lib",
            cve="CVE-2026-0001",
        )

        findings = list_findings_by_scan(db, "scan_001")

        assert isinstance(first, Finding)
        assert isinstance(second, Finding)
        assert [finding.id for finding in findings] == ["finding_001", "finding_002"]
        assert findings[0].file_path == "src/user.py"
        assert findings[0].line == 42
        assert findings[1].component == "demo-lib"
    finally:
        db.close()


def test_get_finding(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan(
            db,
            scan_id="scan_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="created",
        )
        create_finding(
            db,
            finding_id="finding_001",
            scan_id="scan_001",
            category="secret",
            scanner="gitleaks",
            severity="high",
            title="Secret detected",
            status="open",
        )

        finding = get_finding(db, "finding_001")

        assert finding is not None
        assert finding.id == "finding_001"
        assert finding.category == "secret"
        assert finding.llm_summary is None
    finally:
        db.close()


def test_create_cce_finding_with_system_setting_values(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan(
            db,
            scan_id="scan_cce",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="created",
        )

        finding = create_finding(
            db,
            finding_id="finding_cce_001",
            scan_id="scan_cce",
            category="cce",
            scanner="openscap",
            severity="high",
            title="SSH root login is enabled",
            status="open",
            rule_id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
            cce_id="CCE-80801-6",
            current_value="PermitRootLogin yes",
            expected_value="PermitRootLogin no",
            raw_json_path="data/scans/scan_cce/raw/openscap.xml",
        )

        saved = get_finding(db, "finding_cce_001")

        assert finding.category == "cce"
        assert saved is not None
        assert saved.scanner == "openscap"
        assert saved.rule_id == "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
        assert saved.cce_id == "CCE-80801-6"
        assert saved.current_value == "PermitRootLogin yes"
        assert saved.expected_value == "PermitRootLogin no"
    finally:
        db.close()


def test_update_finding_llm_summary(tmp_path):
    db = make_session(tmp_path)
    try:
        create_scan(
            db,
            scan_id="scan_001",
            project_name="demo",
            target_path="C:/AI/projects/demo",
            status="created",
        )
        create_finding(
            db,
            finding_id="finding_001",
            scan_id="scan_001",
            category="sast",
            scanner="semgrep",
            severity="high",
            title="Potential SQL injection",
            status="open",
        )

        updated = update_finding_llm_summary(
            db,
            finding_id="finding_001",
            llm_summary="Review prepared from scanner evidence.",
        )

        assert updated is not None
        assert updated.llm_summary == "Review prepared from scanner evidence."
    finally:
        db.close()


def test_update_missing_finding_llm_summary_returns_none(tmp_path):
    db = make_session(tmp_path)
    try:
        assert (
            update_finding_llm_summary(
                db,
                finding_id="missing",
                llm_summary="unused",
            )
            is None
        )
    finally:
        db.close()
