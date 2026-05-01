from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.crud.scan import get_scan
from app.crud.task import list_tasks_by_scan
from app.db.base import Base
from app.db.database import get_db_session
from app.main import app


class FakeUuid:
    def __init__(self, value: str):
        self.hex = value


def make_test_client(tmp_path):
    db_path = tmp_path / "api.db"
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db_session() -> Generator[Session, None, None]:
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db_session] = override_get_db_session
    return TestClient(app), session_local


def test_create_scan_api_stores_scan_and_tasks(tmp_path):
    db_path = tmp_path / "api.db"
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db_session() -> Generator[Session, None, None]:
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db_session] = override_get_db_session
    client = TestClient(app)
    try:
        with patch("app.api.scans.run_scan") as run_scan_mock:
            response = client.post(
                "/api/scans",
                json={
                    "project_name": "demo",
                    "target_path": "C:/AI/projects/demo",
                    "scan_types": ["semgrep", "gitleaks", "trivy"],
                    "llm_enabled": True,
                    "run_immediately": False,
                },
            )

        assert response.status_code == 200
        body = response.json()
        assert body["scan_id"].startswith("scan_")
        assert body["status"] == "queued"
        run_scan_mock.assert_not_called()

        db = session_local()
        try:
            scan = get_scan(db, body["scan_id"])
            tasks = list_tasks_by_scan(db, body["scan_id"])
        finally:
            db.close()

        assert scan is not None
        assert scan.project_name == "demo"
        assert scan.target_path == "C:/AI/projects/demo"
        assert scan.status == "queued"
        assert {task.tool_name for task in tasks} == {"semgrep", "gitleaks", "trivy"}
        assert {task.status for task in tasks} == {"queued"}
        assert {task.task_type for task in tasks} == {"scanner"}
    finally:
        app.dependency_overrides.clear()


def test_create_scan_api_adds_syft_before_grype_when_grype_requested(tmp_path):
    client, session_local = make_test_client(tmp_path)
    try:
        with (
            patch(
                "app.api.scans.uuid4",
                side_effect=[
                    FakeUuid("0000"),
                    FakeUuid("0001"),
                    FakeUuid("0002"),
                ],
            ),
            patch("app.api.scans.run_scan"),
        ):
            response = client.post(
                "/api/scans",
                json={
                    "project_name": "demo",
                    "target_path": "C:/AI/projects/demo",
                    "scan_types": ["grype"],
                    "llm_enabled": True,
                    "run_immediately": False,
                },
            )

        assert response.status_code == 200
        scan_id = response.json()["scan_id"]

        db = session_local()
        try:
            tasks = list_tasks_by_scan(db, scan_id)
        finally:
            db.close()

        assert [task.tool_name for task in tasks] == ["syft", "grype"]
    finally:
        app.dependency_overrides.clear()


def test_create_scan_api_creates_new_scan_types_in_required_order(tmp_path):
    client, session_local = make_test_client(tmp_path)
    try:
        with (
            patch(
                "app.api.scans.uuid4",
                side_effect=[
                    FakeUuid("0000"),
                    FakeUuid("0001"),
                    FakeUuid("0002"),
                    FakeUuid("0003"),
                    FakeUuid("0004"),
                    FakeUuid("0005"),
                ],
            ),
            patch("app.api.scans.run_scan"),
        ):
            response = client.post(
                "/api/scans",
                json={
                    "project_name": "demo",
                    "target_path": "C:/AI/projects/demo",
                    "scan_types": ["semgrep", "grype", "gitleaks", "trivy", "syft"],
                    "llm_enabled": True,
                    "run_immediately": False,
                },
            )

        assert response.status_code == 200
        scan_id = response.json()["scan_id"]

        db = session_local()
        try:
            tasks = list_tasks_by_scan(db, scan_id)
        finally:
            db.close()

        assert [task.tool_name for task in tasks] == [
            "syft",
            "grype",
            "trivy",
            "semgrep",
            "gitleaks",
        ]
    finally:
        app.dependency_overrides.clear()


def test_create_scan_api_runs_scan_immediately_when_requested(tmp_path):
    db_path = tmp_path / "api_run.db"
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db_session() -> Generator[Session, None, None]:
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db_session] = override_get_db_session
    client = TestClient(app)
    try:
        def fake_run_scan(scan_id: str) -> None:
            db = session_local()
            try:
                scan = get_scan(db, scan_id)
                assert scan is not None
                scan.status = "completed"
                db.commit()
            finally:
                db.close()

        with patch("app.api.scans.run_scan", side_effect=fake_run_scan) as run_scan_mock:
            response = client.post(
                "/api/scans",
                json={
                    "project_name": "demo",
                    "target_path": "C:/AI/projects/demo",
                    "scan_types": ["semgrep", "gitleaks"],
                    "llm_enabled": True,
                    "run_immediately": True,
                },
            )

        assert response.status_code == 200
        body = response.json()
        assert body["scan_id"].startswith("scan_")
        assert body["status"] == "completed"
        run_scan_mock.assert_called_once()

        db = session_local()
        try:
            scan = get_scan(db, body["scan_id"])
            tasks = list_tasks_by_scan(db, body["scan_id"])
        finally:
            db.close()

        assert scan is not None
        assert scan.status == "completed"
        assert {task.tool_name for task in tasks} == {"semgrep", "gitleaks"}
        assert {task.status for task in tasks} == {"queued"}
    finally:
        app.dependency_overrides.clear()


def test_scan_query_apis_return_scan_and_tasks(tmp_path):
    db_path = tmp_path / "query_api.db"
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db_session() -> Generator[Session, None, None]:
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db_session] = override_get_db_session
    client = TestClient(app)
    try:
        created = client.post(
            "/api/scans",
            json={
                "project_name": "demo",
                "target_path": "C:/AI/projects/demo",
                "scan_types": ["semgrep", "gitleaks"],
                "llm_enabled": True,
            },
        ).json()

        list_response = client.get("/api/scans")
        detail_response = client.get(f"/api/scans/{created['scan_id']}")
        tasks_response = client.get(f"/api/scans/{created['scan_id']}/tasks")

        assert list_response.status_code == 200
        assert [scan["id"] for scan in list_response.json()] == [created["scan_id"]]

        assert detail_response.status_code == 200
        assert detail_response.json()["id"] == created["scan_id"]
        assert detail_response.json()["project_name"] == "demo"
        assert detail_response.json()["status"] == "queued"

        assert tasks_response.status_code == 200
        tasks = tasks_response.json()
        assert {task["tool_name"] for task in tasks} == {"semgrep", "gitleaks"}
        assert {task["status"] for task in tasks} == {"queued"}
    finally:
        app.dependency_overrides.clear()


def test_scan_query_apis_return_404_for_missing_scan(tmp_path):
    db_path = tmp_path / "missing_api.db"
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db_session() -> Generator[Session, None, None]:
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db_session] = override_get_db_session
    client = TestClient(app)
    try:
        detail_response = client.get("/api/scans/missing")
        tasks_response = client.get("/api/scans/missing/tasks")

        assert detail_response.status_code == 404
        assert tasks_response.status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_create_scan_api_allows_target_inside_configured_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo"
    monkeypatch.setenv("LOCALSC_WORKSPACE", str(workspace))

    client, session_local = make_test_client(tmp_path)
    try:
        response = client.post(
            "/api/scans",
            json={
                "project_name": "demo",
                "target_path": str(target),
                "scan_types": ["semgrep"],
                "llm_enabled": True,
                "run_immediately": False,
            },
        )

        assert response.status_code == 200
        body = response.json()

        db = session_local()
        try:
            scan = get_scan(db, body["scan_id"])
        finally:
            db.close()

        assert scan is not None
        assert scan.target_path == str(target)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    "target_factory",
    [
        lambda workspace, tmp_path: tmp_path / "outside",
        lambda workspace, tmp_path: workspace / ".." / "outside",
        lambda workspace, tmp_path: Path(str(workspace) + "_outside"),
    ],
)
def test_create_scan_api_rejects_targets_outside_workspace(
    tmp_path,
    monkeypatch,
    target_factory,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("LOCALSC_WORKSPACE", str(workspace))
    target = target_factory(workspace, tmp_path)

    client, session_local = make_test_client(tmp_path)
    try:
        response = client.post(
            "/api/scans",
            json={
                "project_name": "demo",
                "target_path": str(target),
                "scan_types": ["semgrep"],
                "llm_enabled": True,
                "run_immediately": False,
            },
        )

        assert response.status_code == 400
        assert "target_path must be inside workspace" in response.json()["detail"]

        db = session_local()
        try:
            assert get_scan(db, "scan_missing") is None
            assert len(list_tasks_by_scan(db, "scan_missing")) == 0
        finally:
            db.close()
    finally:
        app.dependency_overrides.clear()
