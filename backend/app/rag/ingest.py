from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy.orm import Session

from app.rag.models import RagDocumentChunk


@dataclass(frozen=True)
class MarkdownChunk:
    content: str
    chunk_index: int
    char_start: int
    char_end: int


def split_markdown_chunks(markdown_text: str, chunk_size: int = 1000) -> list[MarkdownChunk]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than 0")

    chunks: list[MarkdownChunk] = []
    text_length = len(markdown_text)
    start = 0

    while start < text_length:
        end = min(start + chunk_size, text_length)
        content = markdown_text[start:end]
        if content.strip():
            chunks.append(
                MarkdownChunk(
                    content=content,
                    chunk_index=len(chunks),
                    char_start=start,
                    char_end=end,
                )
            )
        start = end

    return chunks


def _chunk_id(source_path: Path, chunk_index: int, content: str) -> str:
    fingerprint = f"{source_path.as_posix()}|{chunk_index}|{content}"
    return f"rag_chunk_{uuid5(NAMESPACE_URL, fingerprint).hex}"


def _ensure_rag_tables(db: Session) -> None:
    RagDocumentChunk.__table__.create(bind=db.get_bind(), checkfirst=True)


def ingest_markdown_directory(
    source_dir: str | Path,
    db: Session,
    *,
    chunk_size: int = 1000,
) -> list[RagDocumentChunk]:
    root = Path(source_dir)
    if not root.is_dir():
        raise ValueError(f"source_dir is not a directory: {root}")

    _ensure_rag_tables(db)
    saved_chunks: list[RagDocumentChunk] = []

    for markdown_path in sorted(root.rglob("*.md")):
        markdown_text = markdown_path.read_text(encoding="utf-8")
        chunks = split_markdown_chunks(markdown_text, chunk_size=chunk_size)

        for chunk in chunks:
            metadata = {
                "source_path": str(markdown_path),
                "source_name": markdown_path.name,
                "chunk_index": chunk.chunk_index,
                "char_start": chunk.char_start,
                "char_end": chunk.char_end,
                "chunk_size": chunk_size,
            }
            saved = RagDocumentChunk(
                id=_chunk_id(markdown_path, chunk.chunk_index, chunk.content),
                source_path=str(markdown_path),
                source_name=markdown_path.name,
                chunk_index=chunk.chunk_index,
                content=chunk.content,
                chunk_metadata=json.dumps(metadata, ensure_ascii=False, sort_keys=True),
            )
            db.merge(saved)
            saved_chunks.append(saved)

    db.commit()
    return saved_chunks
