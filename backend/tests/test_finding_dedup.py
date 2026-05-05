from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud.finding import create_finding, list_findings_by_scan
from app.crud.scan import create_scan
from app.db.base import Base
from app.services.finding_dedup import detected_by_from_json


def make_session(tmp_path):
    db_path = tmp_path / "finding_dedup.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def create_test_scan(db):
    return create_scan(
        db,
        scan_id="scan_dedup",
        project_name="demo",
        target_path="C:/AI/projects/demo",
        status="queued",
        created_at=datetime(2026, 5, 1, 10, 0, 0),
    )


def test_create_finding_deduplicates_same_cve_component_and_version(tmp_path):
    db = make_session(tmp_path)
    try:
        scan = create_test_scan(db)

        first = create_finding(
            db,
            finding_id="finding_trivy",
            scan_id=scan.id,
            category="cve",
            scanner="trivy",
            severity="high",
            title="CVE-2026-1000 in lodash",
            status="open",
            component="lodash",
            installed_version="4.17.20",
            fixed_version="4.17.21",
            cve="CVE-2026-1000",
        )
        second = create_finding(
            db,
            finding_id="finding_grype",
            scan_id=scan.id,
            category="cve",
            scanner="grype",
            severity="high",
            title="CVE-2026-1000 in lodash",
            status="open",
            component="lodash",
            installed_version="4.17.20",
            fixed_version="4.17.21",
            cve="CVE-2026-1000",
        )

        findings = list_findings_by_scan(db, scan.id)

        assert second.id == first.id
        assert len(findings) == 1
        assert detected_by_from_json(findings[0].detected_by) == ["trivy", "grype"]
    finally:
        db.close()


def test_create_finding_keeps_same_cve_for_different_component_separate(tmp_path):
    db = make_session(tmp_path)
    try:
        scan = create_test_scan(db)

        create_finding(
            db,
            finding_id="finding_lodash",
            scan_id=scan.id,
            category="cve",
            scanner="trivy",
            severity="high",
            title="CVE-2026-1000 in lodash",
            status="open",
            component="lodash",
            installed_version="4.17.20",
            cve="CVE-2026-1000",
        )
        create_finding(
            db,
            finding_id="finding_express",
            scan_id=scan.id,
            category="cve",
            scanner="grype",
            severity="high",
            title="CVE-2026-1000 in express",
            status="open",
            component="express",
            installed_version="4.17.20",
            cve="CVE-2026-1000",
        )

        findings = list_findings_by_scan(db, scan.id)

        assert len(findings) == 2
        assert {finding.component for finding in findings} == {"lodash", "express"}
    finally:
        db.close()


def test_create_finding_does_not_deduplicate_superseded_cve(tmp_path):
    db = make_session(tmp_path)
    try:
        scan = create_test_scan(db)

        create_finding(
            db,
            finding_id="finding_old",
            scan_id=scan.id,
            category="cve",
            scanner="trivy",
            severity="high",
            title="CVE-2026-1000 in lodash",
            status="superseded",
            component="lodash",
            installed_version="4.17.20",
            fixed_version="4.17.21",
            cve="CVE-2026-1000",
        )
        new_finding = create_finding(
            db,
            finding_id="finding_new",
            scan_id=scan.id,
            category="cve",
            scanner="trivy",
            severity="high",
            title="CVE-2026-1000 in lodash",
            status="open",
            component="lodash",
            installed_version="4.17.20",
            fixed_version="4.17.21",
            cve="CVE-2026-1000",
        )

        findings = list_findings_by_scan(db, scan.id)

        assert new_finding.id == "finding_new"
        assert len(findings) == 2
        assert {finding.status for finding in findings} == {"open", "superseded"}
    finally:
        db.close()
