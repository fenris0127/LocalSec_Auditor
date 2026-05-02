from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.finding import create_finding
from app.crud.project import create_project
from app.crud.scan import create_scan
from app.db.base import Base
from app.services.scan_compare import compare_scans


def make_session(tmp_path):
    db_path = tmp_path / "scan_compare.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def create_project_scans(db):
    create_project(
        db,
        project_id="project_001",
        name="demo",
        root_path="C:/AI/projects/demo",
        created_at=datetime(2026, 5, 2, 9, 0, 0),
    )
    create_scan(
        db,
        scan_id="scan_base",
        project_id="project_001",
        project_name="demo",
        target_path="C:/AI/projects/demo",
        status="completed",
        created_at=datetime(2026, 5, 2, 10, 0, 0),
    )
    create_scan(
        db,
        scan_id="scan_target",
        project_id="project_001",
        project_name="demo",
        target_path="C:/AI/projects/demo",
        status="completed",
        created_at=datetime(2026, 5, 2, 11, 0, 0),
    )


def test_compare_scans_classifies_new_resolved_and_persistent_findings(tmp_path):
    db = make_session(tmp_path)
    try:
        create_project_scans(db)
        create_finding(
            db,
            finding_id="base_persistent",
            scan_id="scan_base",
            category="sast",
            scanner="semgrep",
            severity="high",
            title="Persistent SQL injection",
            status="open",
            rule_id="python.sql-injection",
            file_path="src/user.py",
            line=42,
            cwe="CWE-89",
        )
        create_finding(
            db,
            finding_id="base_resolved",
            scan_id="scan_base",
            category="cve",
            scanner="trivy",
            severity="medium",
            title="Resolved vulnerable dependency",
            status="open",
            component="demo-lib",
            installed_version="1.0.0",
            cve="CVE-2026-0001",
        )
        create_finding(
            db,
            finding_id="target_persistent",
            scan_id="scan_target",
            category="sast",
            scanner="semgrep",
            severity="critical",
            title="Persistent SQL injection with updated severity",
            status="open",
            rule_id="python.sql-injection",
            file_path="src/user.py",
            line=42,
            cwe="CWE-89",
        )
        create_finding(
            db,
            finding_id="target_new",
            scan_id="scan_target",
            category="secret",
            scanner="gitleaks",
            severity="high",
            title="New secret finding",
            status="open",
            rule_id="generic-api-key",
            file_path="src/config.py",
            line=7,
        )

        result = compare_scans("scan_base", "scan_target", db=db)

        assert [finding.id for finding in result.new_findings] == ["target_new"]
        assert [finding.id for finding in result.resolved_findings] == ["base_resolved"]
        assert [finding.id for finding in result.persistent_findings] == ["target_persistent"]
    finally:
        db.close()


def test_compare_scans_includes_severity_and_category_stats(tmp_path):
    db = make_session(tmp_path)
    try:
        create_project_scans(db)
        create_finding(
            db,
            finding_id="base_resolved",
            scan_id="scan_base",
            category="cve",
            scanner="trivy",
            severity="medium",
            title="Resolved vulnerable dependency",
            status="open",
            component="demo-lib",
            cve="CVE-2026-0001",
        )
        create_finding(
            db,
            finding_id="target_new",
            scan_id="scan_target",
            category="cce",
            scanner="openscap",
            severity="high",
            title="New SSH configuration finding",
            status="open",
            rule_id="sshd_disable_root_login",
            cce_id="CCE-80801-6",
        )

        result = compare_scans("scan_base", "scan_target", db=db)

        assert result.stats["new_findings"].total == 1
        assert result.stats["new_findings"].by_severity == {"high": 1}
        assert result.stats["new_findings"].by_category == {"cce": 1}
        assert result.stats["resolved_findings"].total == 1
        assert result.stats["resolved_findings"].by_severity == {"medium": 1}
        assert result.stats["resolved_findings"].by_category == {"cve": 1}
        assert result.stats["persistent_findings"].total == 0
        assert result.stats["persistent_findings"].by_severity == {}
        assert result.stats["persistent_findings"].by_category == {}
    finally:
        db.close()


def test_compare_scans_rejects_different_projects(tmp_path):
    db = make_session(tmp_path)
    try:
        create_project(
            db,
            project_id="project_base",
            name="base",
            root_path="C:/AI/projects/base",
        )
        create_project(
            db,
            project_id="project_target",
            name="target",
            root_path="C:/AI/projects/target",
        )
        create_scan(
            db,
            scan_id="scan_base",
            project_id="project_base",
            project_name="base",
            target_path="C:/AI/projects/base",
            status="completed",
        )
        create_scan(
            db,
            scan_id="scan_target",
            project_id="project_target",
            project_name="target",
            target_path="C:/AI/projects/target",
            status="completed",
        )

        with pytest.raises(ValueError, match="same project_id"):
            compare_scans("scan_base", "scan_target", db=db)
    finally:
        db.close()
