"""Tests for ollama_client.py. Ollama is mocked: no server needed."""

import requests

import ollama_client as oc


class FakeResponse:
    def __init__(self, body=None, http_error=None, json_error=False):
        self._body, self._http_error, self._json_error = body, http_error, json_error

    def raise_for_status(self):
        if self._http_error:
            raise self._http_error

    def json(self):
        if self._json_error:
            raise ValueError("not json")
        return self._body


def patch_post(monkeypatch, response=None, exc=None):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"], captured["payload"], captured["timeout"] = url, json, timeout
        if exc:
            raise exc
        return response
    monkeypatch.setattr(oc.requests, "post", fake_post)
    return captured


def test_success(monkeypatch):
    patch_post(monkeypatch, FakeResponse({"response": '{"explanation": "x"}'}))
    assert oc.query_ollama("hi") == {"ok": True, "text": '{"explanation": "x"}'}


def test_request_payload(monkeypatch):
    captured = patch_post(monkeypatch, FakeResponse({"response": "{}"}))
    oc.query_ollama("hello")
    payload = captured["payload"]
    assert captured["url"] == "http://localhost:11434/api/generate"
    assert payload["model"] == "qwen2.5:1.5b"
    assert payload["format"] == "json" and payload["stream"] is False
    assert payload["options"]["temperature"] == 0
    assert payload["options"]["num_predict"] > 0


def test_connection_error(monkeypatch):
    patch_post(monkeypatch, exc=requests.exceptions.ConnectionError())
    result = oc.query_ollama("hi")
    assert result["ok"] is False and result["error_kind"] == "connection"


def test_timeout(monkeypatch):
    patch_post(monkeypatch, exc=requests.exceptions.Timeout())
    assert oc.query_ollama("hi")["error_kind"] == "timeout"


def test_http_error(monkeypatch):
    patch_post(monkeypatch, FakeResponse(http_error=requests.exceptions.HTTPError("404")))
    assert oc.query_ollama("hi")["error_kind"] == "http"


def test_non_json_body(monkeypatch):
    patch_post(monkeypatch, FakeResponse(json_error=True))
    assert oc.query_ollama("hi")["error_kind"] == "invalid_response"


def test_body_without_response_field(monkeypatch):
    patch_post(monkeypatch, FakeResponse({"something": "else"}))
    assert oc.query_ollama("hi")["error_kind"] == "invalid_response"


def test_legacy_wrapper_returns_error_string(monkeypatch):
    patch_post(monkeypatch, exc=requests.exceptions.ConnectionError())
    assert oc.analyze_with_ollama("hi").startswith("ERROR:")


def test_check_ollama_not_running(monkeypatch):
    def fake_get(url, timeout=None):
        raise requests.exceptions.ConnectionError()
    monkeypatch.setattr(oc.requests, "get", fake_get)
    status = oc.check_ollama()
    assert status["available"] is False


def test_check_ollama_model_installed(monkeypatch):
    monkeypatch.setattr(oc.requests, "get",
                        lambda url, timeout=None: FakeResponse({"models": [{"name": "qwen2.5:1.5b"}]}))
    status = oc.check_ollama()
    assert status["available"] and status["model_installed"]


def test_check_ollama_model_missing(monkeypatch):
    monkeypatch.setattr(oc.requests, "get",
                        lambda url, timeout=None: FakeResponse({"models": [{"name": "llama3:8b"}]}))
    status = oc.check_ollama()
    assert status["available"] and not status["model_installed"]
    assert "ollama pull qwen2.5:1.5b" in status["message"]
