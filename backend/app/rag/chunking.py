from __future__ import annotations

from dataclasses import dataclass


DEFAULT_CHUNK_SIZE = 1000
DEFAULT_CHUNK_OVERLAP = 150
DEFAULT_MIN_CHUNK_CHARS = 40


@dataclass(frozen=True)
class DocumentChunk:
    content: str
    metadata: dict[str, str | int]


def _extract_title(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or "Untitled"
    return "Untitled"


def chunk_document(
    text: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_CHUNK_OVERLAP,
    *,
    source_path: str = "",
    title: str | None = None,
    min_chunk_chars: int = DEFAULT_MIN_CHUNK_CHARS,
) -> list[DocumentChunk]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than 0")
    if overlap < 0:
        raise ValueError("overlap must be greater than or equal to 0")
    if overlap >= chunk_size:
        raise ValueError("overlap must be smaller than chunk_size")
    if min_chunk_chars < 0:
        raise ValueError("min_chunk_chars must be greater than or equal to 0")

    document_title = title or _extract_title(text)
    chunks: list[DocumentChunk] = []
    start = 0
    step = chunk_size - overlap

    while start < len(text):
        end = min(start + chunk_size, len(text))
        content = text[start:end].strip()
        if len(content) >= min_chunk_chars:
            chunks.append(
                DocumentChunk(
                    content=content,
                    metadata={
                        "source_path": source_path,
                        "chunk_index": len(chunks),
                        "title": document_title,
                    },
                )
            )
        start += step

    return chunks
