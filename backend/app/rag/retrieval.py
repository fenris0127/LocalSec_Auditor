from __future__ import annotations

from typing import Any, Callable

from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.llm.secret_masking import mask_secret_text
from app.rag.embeddings import embed_text
from app.rag.vector_store import VectorSearchResult, similarity_search


Embedder = Callable[[str], list[float]]


def _get_field(finding: Any, field: str) -> Any:
    if isinstance(finding, dict):
        return finding.get(field)
    return getattr(finding, field, None)


def _safe_value(value: Any) -> str | None:
    if value is None:
        return None
    text = mask_secret_text(value).strip()
    return text or None


def build_finding_context_query(finding: Any) -> str:
    fields = ["category", "title", "cve", "cwe", "component"]
    parts = []
    for field in fields:
        value = _safe_value(_get_field(finding, field))
        if value is not None:
            parts.append(f"{field}: {value}")
    return "\n".join(parts)


def retrieve_context_for_finding(
    finding: Any,
    top_k: int = 5,
    *,
    db: Session | None = None,
    embedder: Embedder = embed_text,
) -> list[VectorSearchResult]:
    query = build_finding_context_query(finding)
    if not query:
        return []

    owns_db = db is None
    session = db or SessionLocal()
    try:
        query_embedding = embedder(query)
        return similarity_search(session, query_embedding=query_embedding, top_k=top_k)
    finally:
        if owns_db:
            session.close()
