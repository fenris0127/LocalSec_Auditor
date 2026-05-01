from __future__ import annotations

import json
import math
from dataclasses import dataclass
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.rag.chunking import DocumentChunk
from app.rag.models import RagVectorChunk


@dataclass(frozen=True)
class VectorSearchResult:
    id: str
    content: str
    metadata: dict[str, object]
    score: float


def _ensure_vector_tables(db: Session) -> None:
    RagVectorChunk.__table__.create(bind=db.get_bind(), checkfirst=True)


def _vector_chunk_id(chunk: DocumentChunk) -> str:
    source_path = chunk.metadata.get("source_path", "")
    chunk_index = chunk.metadata.get("chunk_index", "")
    fingerprint = f"{source_path}|{chunk_index}|{chunk.content}"
    return f"rag_vec_{uuid5(NAMESPACE_URL, fingerprint).hex}"


def _serialize_embedding(embedding: list[float]) -> str:
    if not embedding:
        raise ValueError("embedding must not be empty")
    return json.dumps([float(value) for value in embedding])


def _deserialize_embedding(value: str) -> list[float]:
    payload = json.loads(value)
    if not isinstance(payload, list):
        return []
    return [float(item) for item in payload if isinstance(item, int | float)]


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


def save_chunk_embedding(
    db: Session,
    *,
    chunk: DocumentChunk,
    embedding: list[float],
) -> RagVectorChunk:
    _ensure_vector_tables(db)
    row = RagVectorChunk(
        id=_vector_chunk_id(chunk),
        content=chunk.content,
        chunk_metadata=json.dumps(chunk.metadata, ensure_ascii=False, sort_keys=True),
        embedding=_serialize_embedding(embedding),
    )
    saved = db.merge(row)
    db.commit()
    db.refresh(saved)
    return saved


def similarity_search(
    db: Session,
    *,
    query_embedding: list[float],
    top_k: int = 5,
) -> list[VectorSearchResult]:
    if top_k <= 0:
        raise ValueError("top_k must be greater than 0")
    if not query_embedding:
        raise ValueError("query_embedding must not be empty")

    _ensure_vector_tables(db)
    rows = db.scalars(select(RagVectorChunk)).all()
    results = [
        VectorSearchResult(
            id=row.id,
            content=row.content,
            metadata=json.loads(row.chunk_metadata),
            score=_cosine_similarity(query_embedding, _deserialize_embedding(row.embedding)),
        )
        for row in rows
    ]
    return sorted(results, key=lambda result: result.score, reverse=True)[:top_k]
