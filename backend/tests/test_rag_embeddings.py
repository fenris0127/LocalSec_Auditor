import json

import httpx
import pytest

from app.rag.embeddings import EmbeddingError, embed_text


def test_embed_text_calls_ollama_embeddings_with_default_model():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = json.loads(request.content.decode("utf-8"))
        assert body == {
            "model": "bge-m3",
            "prompt": "LocalSec chunk text",
        }
        return httpx.Response(200, json={"embedding": [0.1, 0.2, 0.3]})

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://localhost:11434",
    )

    try:
        embedding = embed_text("LocalSec chunk text", client=client)
    finally:
        client.close()

    assert embedding == [0.1, 0.2, 0.3]
    assert len(requests) == 1
    assert requests[0].url.path == "/api/embeddings"


def test_embed_text_supports_model_override_and_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == "nomic-embed-text"
        return httpx.Response(200, json={"embedding": [1, 2, 3]})

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://localhost:11434",
    )

    try:
        embedding = embed_text(
            "chunk",
            model="nomic-embed-text",
            client=client,
            timeout=3,
        )
    finally:
        client.close()

    assert embedding == [1.0, 2.0, 3.0]


def test_embed_text_raises_clear_error_on_connection_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://localhost:11434",
    )

    try:
        with pytest.raises(EmbeddingError, match="Failed to call Ollama embedding API"):
            embed_text("chunk", client=client)
    finally:
        client.close()


def test_embed_text_raises_clear_error_on_invalid_payload():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"embedding": []})

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://localhost:11434",
    )

    try:
        with pytest.raises(EmbeddingError, match="Invalid Ollama embedding response payload"):
            embed_text("chunk", client=client)
    finally:
        client.close()
