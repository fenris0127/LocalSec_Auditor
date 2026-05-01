from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.rag.chunking import DocumentChunk
from app.rag.retrieval import build_finding_context_query, retrieve_context_for_finding
from app.rag.vector_store import save_chunk_embedding


def make_session(tmp_path):
    db_path = tmp_path / "rag_retrieval.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def test_retrieve_context_for_finding_searches_with_finding_metadata(tmp_path):
    db = make_session(tmp_path)
    finding = {
        "category": "sast",
        "title": "SQL injection in login query",
        "cve": None,
        "cwe": "CWE-89",
        "component": "auth-service",
    }
    captured_queries: list[str] = []

    def fake_embedder(query: str) -> list[float]:
        captured_queries.append(query)
        return [1.0, 0.0]

    try:
        save_chunk_embedding(
            db,
            chunk=DocumentChunk(
                "SQL injection remediation guidance",
                {"source_path": "sql.md", "chunk_index": 0, "title": "SQL Injection"},
            ),
            embedding=[1.0, 0.0],
        )
        save_chunk_embedding(
            db,
            chunk=DocumentChunk(
                "Container image scanning guidance",
                {"source_path": "container.md", "chunk_index": 0, "title": "Container"},
            ),
            embedding=[0.0, 1.0],
        )

        results = retrieve_context_for_finding(finding, top_k=1, db=db, embedder=fake_embedder)

        assert len(results) == 1
        assert results[0].content == "SQL injection remediation guidance"
        assert "category: sast" in captured_queries[0]
        assert "title: SQL injection in login query" in captured_queries[0]
        assert "cwe: CWE-89" in captured_queries[0]
        assert "component: auth-service" in captured_queries[0]
    finally:
        db.close()


def test_build_finding_context_query_masks_secret_like_values():
    secret_value = "sk_test_secret_value"
    finding = {
        "category": "secret",
        "title": f"Secret detected: {secret_value}",
        "cve": None,
        "cwe": None,
        "component": f"env {secret_value}",
    }

    query = build_finding_context_query(finding)

    assert secret_value not in query
    assert "[REDACTED_SECRET]" in query
    assert "category: secret" in query


def test_retrieve_context_for_finding_returns_empty_without_query(tmp_path):
    db = make_session(tmp_path)
    try:
        assert retrieve_context_for_finding({}, db=db, embedder=lambda query: [1.0]) == []
    finally:
        db.close()
