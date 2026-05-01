from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.rag.chunking import DocumentChunk
from app.rag.models import RagVectorChunk
from app.rag.vector_store import save_chunk_embedding, similarity_search


def make_session(tmp_path):
    db_path = tmp_path / "rag_vectors.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def test_save_chunk_embedding_stores_text_metadata_and_embedding(tmp_path):
    db = make_session(tmp_path)
    chunk = DocumentChunk(
        content="SQL injection remediation guidance",
        metadata={
            "source_path": "docs/rag_sources/sql.md",
            "chunk_index": 0,
            "title": "SQL Injection",
        },
    )

    try:
        saved = save_chunk_embedding(db, chunk=chunk, embedding=[1.0, 0.0, 0.0])
        row = db.get(RagVectorChunk, saved.id)

        assert row is not None
        assert row.content == "SQL injection remediation guidance"
        assert "SQL Injection" in row.chunk_metadata
        assert row.embedding == "[1.0, 0.0, 0.0]"
    finally:
        db.close()


def test_similarity_search_returns_top_k_results_by_query_embedding(tmp_path):
    db = make_session(tmp_path)
    chunks = [
        DocumentChunk("SQL injection prevention", {"source_path": "a.md", "chunk_index": 0, "title": "SQL"}),
        DocumentChunk("Container image scanning", {"source_path": "b.md", "chunk_index": 0, "title": "Container"}),
        DocumentChunk("Password rotation policy", {"source_path": "c.md", "chunk_index": 0, "title": "Secrets"}),
    ]

    try:
        save_chunk_embedding(db, chunk=chunks[0], embedding=[1.0, 0.0, 0.0])
        save_chunk_embedding(db, chunk=chunks[1], embedding=[0.0, 1.0, 0.0])
        save_chunk_embedding(db, chunk=chunks[2], embedding=[0.9, 0.1, 0.0])

        results = similarity_search(db, query_embedding=[1.0, 0.0, 0.0], top_k=2)

        assert [result.content for result in results] == [
            "SQL injection prevention",
            "Password rotation policy",
        ]
        assert results[0].score > results[1].score
        assert results[0].metadata["title"] == "SQL"
    finally:
        db.close()


def test_similarity_search_rejects_invalid_top_k(tmp_path):
    db = make_session(tmp_path)
    try:
        try:
            similarity_search(db, query_embedding=[1.0], top_k=0)
        except ValueError as exc:
            assert "top_k must be greater than 0" in str(exc)
        else:
            raise AssertionError("Expected ValueError")
    finally:
        db.close()
