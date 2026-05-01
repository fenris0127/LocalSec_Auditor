from __future__ import annotations

import json

import httpx

from app.core.config import get_ollama_settings


class OllamaError(RuntimeError):
    pass


def _build_client(timeout: float | None = None) -> httpx.Client:
    settings = get_ollama_settings()
    return httpx.Client(base_url=settings.base_url, timeout=timeout or settings.timeout_seconds)


def generate(
    prompt: str,
    *,
    client: httpx.Client | None = None,
    timeout: float | None = None,
) -> str:
    settings = get_ollama_settings()
    owns_client = client is None
    session = client or _build_client(timeout=timeout)

    payload = {
        "model": settings.model,
        "prompt": prompt,
        "stream": False,
    }

    try:
        response = session.post("/api/generate", json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or "response" not in data:
            raise OllamaError("Invalid Ollama response payload")
        return str(data["response"])
    except httpx.HTTPStatusError as exc:
        raise OllamaError(f"Ollama request failed with status {exc.response.status_code}") from exc
    except (httpx.RequestError, httpx.TimeoutException, json.JSONDecodeError, ValueError) as exc:
        raise OllamaError(f"Failed to call Ollama at {settings.base_url}") from exc
    finally:
        if owns_client:
            session.close()
