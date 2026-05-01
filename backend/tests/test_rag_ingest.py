import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.rag.ingest import ingest_markdown_directory, split_markdown_chunks
from app.rag.models import RagDocumentChunk


def make_session(tmp_path):
    db_path = tmp_path / "rag.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_local()


def test_split_markdown_chunks_respects_chunk_size():
    chunks = split_markdown_chunks("# Title\n\nabcdef", chunk_size=5)

    assert [chunk.content for chunk in chunks] == ["# Tit", "le\n\na", "bcdef"]
    assert chunks[0].chunk_index == 0
    assert chunks[1].char_start == 5
    assert chunks[2].char_end == 15


def test_ingest_markdown_directory_saves_chunks_with_metadata(tmp_path):
    source_dir = tmp_path / "rag_sources"
    source_dir.mkdir()
    sample = source_dir / "sample.md"
    sample.write_text("# Sample\n\nLocalSec RAG markdown source.", encoding="utf-8")
    db = make_session(tmp_path)

    try:
        saved = ingest_markdown_directory(source_dir, db, chunk_size=12)
        rows = db.scalars(
            select(RagDocumentChunk).order_by(RagDocumentChunk.source_name, RagDocumentChunk.chunk_index)
        ).all()

        assert len(saved) == 4
        assert len(rows) == 4
        assert rows[0].source_name == "sample.md"
        assert rows[0].content == "# Sample\n\nLo"

        metadata = json.loads(rows[0].chunk_metadata)
        assert metadata["source_name"] == "sample.md"
        assert metadata["chunk_index"] == 0
        assert metadata["char_start"] == 0
        assert metadata["char_end"] == 12
        assert metadata["chunk_size"] == 12
    finally:
        db.close()


def test_ingest_markdown_directory_uses_local_markdown_files_only(tmp_path):
    source_dir = tmp_path / "rag_sources"
    source_dir.mkdir()
    (source_dir / "a.md").write_text("markdown", encoding="utf-8")
    (source_dir / "ignored.txt").write_text("not markdown", encoding="utf-8")
    db = make_session(tmp_path)

    try:
        ingest_markdown_directory(source_dir, db, chunk_size=100)
        rows = db.scalars(select(RagDocumentChunk)).all()

        assert len(rows) == 1
        assert rows[0].source_name == "a.md"
        assert rows[0].content == "markdown"
    finally:
        db.close()
