import pytest

from app.rag.chunking import chunk_document


def test_chunk_document_splits_sample_document_into_multiple_chunks():
    text = "# Access Control\n\n" + "A" * 35 + "\n\n" + "B" * 35 + "\n\n" + "C" * 35

    chunks = chunk_document(
        text,
        chunk_size=50,
        overlap=10,
        source_path="docs/rag_sources/access-control.md",
        min_chunk_chars=20,
    )

    assert len(chunks) >= 3
    assert chunks[0].metadata == {
        "source_path": "docs/rag_sources/access-control.md",
        "chunk_index": 0,
        "title": "Access Control",
    }
    assert [chunk.metadata["chunk_index"] for chunk in chunks] == list(range(len(chunks)))


def test_chunk_document_applies_overlap():
    text = "abcdefghijklmnopqrstuvwxyz"

    chunks = chunk_document(text, chunk_size=10, overlap=3, min_chunk_chars=1)

    assert chunks[0].content == "abcdefghij"
    assert chunks[1].content == "hijklmnopq"
    assert chunks[0].content[-3:] == chunks[1].content[:3]


def test_chunk_document_excludes_too_short_chunks():
    text = "abcdefghij" + "klm"

    chunks = chunk_document(text, chunk_size=10, overlap=0, min_chunk_chars=5)

    assert [chunk.content for chunk in chunks] == ["abcdefghij"]


def test_chunk_document_rejects_invalid_overlap():
    with pytest.raises(ValueError, match="overlap must be smaller than chunk_size"):
        chunk_document("content", chunk_size=10, overlap=10)
