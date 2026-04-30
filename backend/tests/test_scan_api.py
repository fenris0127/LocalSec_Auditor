from collections.abc import Generator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.crud.scan import get_scan
from app.crud.task import list_tasks_by_scan
from app.db.base import Base
from app.db.database import get_db_session
from app.main import app


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
        response = client.post(
            "/api/scans",
            json={
                "project_name": "demo",
                "target_path": "C:/AI/projects/demo",
                "scan_types": ["semgrep", "gitleaks", "trivy"],
                "llm_enabled": True,
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["scan_id"].startswith("scan_")
        assert body["status"] == "queued"

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
        assert [task.tool_name for task in tasks] == ["semgrep", "gitleaks", "trivy"]
        assert {task.status for task in tasks} == {"queued"}
        assert {task.task_type for task in tasks} == {"scanner"}
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
        assert [task["tool_name"] for task in tasks] == ["semgrep", "gitleaks"]
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
