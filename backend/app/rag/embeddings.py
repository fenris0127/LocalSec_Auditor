from __future__ import annotations

import json
import os

import httpx

from app.core.config import get_ollama_settings


DEFAULT_EMBEDDING_MODEL = "bge-m3"
EMBEDDING_MODEL_ENV = "OLLAMA_EMBEDDING_MODEL"


class EmbeddingError(RuntimeError):
    pass


def get_embedding_model() -> str:
    return os.getenv(EMBEDDING_MODEL_ENV, DEFAULT_EMBEDDING_MODEL)


def _build_client(timeout: float | None = None) -> httpx.Client:
    settings = get_ollama_settings()
    return httpx.Client(base_url=settings.base_url, timeout=timeout or settings.timeout_seconds)


def _validate_embedding(value: object) -> list[float]:
    if not isinstance(value, list) or not value:
        raise EmbeddingError("Invalid Ollama embedding response payload")

    embedding: list[float] = []
    for item in value:
        if not isinstance(item, int | float):
            raise EmbeddingError("Invalid Ollama embedding response payload")
        embedding.append(float(item))
    return embedding


def embed_text(
    text: str,
    *,
    model: str | None = None,
    client: httpx.Client | None = None,
    timeout: float | None = None,
) -> list[float]:
    settings = get_ollama_settings()
    owns_client = client is None
    session = client or _build_client(timeout=timeout)
    payload = {
        "model": model or get_embedding_model(),
        "prompt": text,
    }

    try:
        response = session.post("/api/embeddings", json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or "embedding" not in data:
            raise EmbeddingError("Invalid Ollama embedding response payload")
        return _validate_embedding(data["embedding"])
    except EmbeddingError:
        raise
    except httpx.HTTPStatusError as exc:
        raise EmbeddingError(
            f"Ollama embedding request failed with status {exc.response.status_code}"
        ) from exc
    except (httpx.RequestError, httpx.TimeoutException, json.JSONDecodeError, ValueError) as exc:
        raise EmbeddingError(f"Failed to call Ollama embedding API at {settings.base_url}") from exc
    finally:
        if owns_client:
            session.close()
