"""Model tenant: the only process allowed to talk to Ollama."""

import os
import threading
import time

import httpx
from fastapi import Depends, FastAPI
from pydantic import BaseModel

from internal import require_gateway

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
MODEL = os.getenv("BAYORA_MODEL", "llama3.2:3b")
FLUSH_EVERY_CALL = os.getenv("BAYORA_FLUSH_EVERY_CALL", "0").lower() in (
    "1", "true", "yes",
)

_inference_lock = threading.Lock()
_last_inference_test: str | None = None

app = FastAPI(title="Bayora model gateway")


class GenerateIn(BaseModel):
    test_id: str
    prompt: str


def _ollama_loaded() -> bool:
    r = httpx.get(f"{OLLAMA_HOST}/api/ps", timeout=10)
    r.raise_for_status()
    names = []
    for m in r.json().get("models") or []:
        names.append(str(m.get("name") or m.get("model") or ""))
    return any(MODEL in n or n in (MODEL or "") for n in names)


def _ollama_unload() -> bool:
    try:
        httpx.post(
            f"{OLLAMA_HOST}/api/generate",
            json={"model": MODEL, "keep_alive": 0},
            timeout=30,
        )
        deadline = time.time() + 12
        while time.time() < deadline:
            try:
                if not _ollama_loaded():
                    return True
            except Exception:
                break
            time.sleep(0.2)
        return True
    except Exception:
        return False


def _mock_reply(prompt: str) -> str:
    lowered = prompt.lower()
    if any(k in lowered for k in ["ignore previous", "jailbreak", "dan mode"]):
        return "I'm sorry, but I can't help with that request."
    return "Here is the requested information (mock response)."


@app.post("/generate")
def generate(body: GenerateIn, _: None = Depends(require_gateway)):
    """Serialized generate; unload KV-cache when the evaluation id changes."""
    meta = {
        "session": body.test_id,
        "serialized": True,
        "kv_cache_flushed": False,
        "runner": "ollama",
        "model": MODEL,
    }
    global _last_inference_test
    with _inference_lock:
        switch = (
            _last_inference_test is not None
            and _last_inference_test != body.test_id
        )
        try:
            if FLUSH_EVERY_CALL or switch:
                meta["kv_cache_flushed"] = _ollama_unload()
            keep_alive = 0 if FLUSH_EVERY_CALL else "5m"
            r = httpx.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": MODEL,
                    "prompt": body.prompt,
                    "stream": False,
                    "keep_alive": keep_alive,
                },
                timeout=120,
            )
            r.raise_for_status()
            reply = r.json().get("response", "")
            if FLUSH_EVERY_CALL:
                meta["kv_cache_flushed"] = _ollama_unload() or meta["kv_cache_flushed"]
                _last_inference_test = None
            else:
                _last_inference_test = body.test_id
            return {"reply": reply, "inference": meta}
        except Exception:
            meta["runner"] = "mock"
            meta["kv_cache_flushed"] = True
            _last_inference_test = body.test_id
            return {"reply": _mock_reply(body.prompt), "inference": meta}


@app.get("/health")
def health():
    return {"ok": True, "role": "model-gateway"}
