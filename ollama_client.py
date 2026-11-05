"""
ollama_client.py - Talks to a locally running Ollama server. No API key, no internet.

query_ollama()   -> structured result {"ok": bool, ...}  (used by analyzer.py)
check_ollama()   -> is the server up, and is the model installed?
analyze_with_ollama() -> old string-returning helper, kept for backward compatibility.
"""

import os
import requests

OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://localhost:11434"
).rstrip("/")

OLLAMA_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"

MODEL_NAME = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")

CONNECT_TIMEOUT_SECONDS = 5
READ_TIMEOUT_SECONDS = 180   # per request; analyzer makes one small request per finding

# Deterministic, short, bounded generation. Small models behave better this way.
GENERATION_OPTIONS = {
    "temperature": 0,     # same input -> same output (as far as possible)
    "num_ctx": 4096,      # context window; Ollama's default can silently truncate long prompts
    "num_predict": 400,   # hard cap on the number of generated tokens
}


def query_ollama(prompt: str, model: str = None) -> dict:
    """
    Send one prompt to Ollama.

    Success: {"ok": True, "text": "<model output>"}
    Failure: {"ok": False, "error_kind": "connection|timeout|http|invalid_response|request",
              "error": "<human-readable message>"}
    """
    model = model or MODEL_NAME
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": GENERATION_OPTIONS,
        "keep_alive": "10m",   # keep the model loaded between findings
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS),
        )
        response.raise_for_status()
        body = response.json()
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error_kind": "connection",
                "error": "Ollama is not running. Start it, then try again."}
    except requests.exceptions.Timeout:
        return {"ok": False, "error_kind": "timeout",
                "error": "The model took too long to respond."}
    except requests.exceptions.HTTPError as error:
        return {"ok": False, "error_kind": "http",
                "error": f"Ollama returned an error: {error}"}
    except ValueError:  # response body was not JSON
        return {"ok": False, "error_kind": "invalid_response",
                "error": "Ollama returned a response that was not valid JSON."}
    except requests.exceptions.RequestException as error:
        return {"ok": False, "error_kind": "request", "error": str(error)}

    if not isinstance(body, dict) or not isinstance(body.get("response"), str):
        return {"ok": False, "error_kind": "invalid_response",
                "error": "Ollama response did not contain model text."}

    return {"ok": True, "text": body["response"]}


def check_ollama(model: str = None) -> dict:
    """
    Check that the Ollama server is reachable and the model is installed.
    Returns {"available": bool, "model_installed": bool, "message": str}.
    """
    model = model or MODEL_NAME
    try:
        response = requests.get(OLLAMA_TAGS_URL, timeout=3)
        response.raise_for_status()
        models = response.json().get("models", [])
    except requests.exceptions.ConnectionError:
        return {"available": False, "model_installed": False,
                "message": "Ollama is not running."}
    except (requests.exceptions.RequestException, ValueError, AttributeError) as error:
        return {"available": False, "model_installed": False,
                "message": f"Could not query Ollama: {error}"}

    names = {m.get("name") or m.get("model") for m in models if isinstance(m, dict)}
    if model not in names:
        return {"available": True, "model_installed": False,
                "message": f"Ollama is running, but model '{model}' is not installed. "
                           f"Run: ollama pull {model}"}

    return {"available": True, "model_installed": True,
            "message": f"Ollama is running with model '{model}'."}


def analyze_with_ollama(prompt: str) -> str:
    """Backward-compatible wrapper: returns the model text, or a string starting with 'ERROR:'."""
    result = query_ollama(prompt)
    if result["ok"]:
        return result["text"]
    return f"ERROR: {result['error']}"
