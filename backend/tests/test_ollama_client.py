import json

import httpx
import pytest

from app.llm.client import OllamaError, generate


def test_generate_calls_ollama_with_expected_payload(monkeypatch):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = json.loads(request.content.decode("utf-8"))
        assert body == {
            "model": "localsec-security",
            "prompt": "Summarize this finding",
            "stream": False,
        }
        return httpx.Response(200, json={"response": "analysis result"})

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://localhost:11434",
    )

    try:
        result = generate("Summarize this finding", client=client)
    finally:
        client.close()

    assert result == "analysis result"
    assert len(requests) == 1
    assert requests[0].url.path == "/api/generate"


def test_generate_raises_clear_error_on_connection_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://localhost:11434",
    )

    try:
        with pytest.raises(OllamaError, match="Failed to call Ollama"):
            generate("Summarize this finding", client=client)
    finally:
        client.close()


def test_generate_raises_clear_error_on_invalid_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "payload"})

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://localhost:11434",
    )

    try:
        with pytest.raises(OllamaError, match="Invalid Ollama response payload"):
            generate("Summarize this finding", client=client)
    finally:
        client.close()
