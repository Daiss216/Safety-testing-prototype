"""Blue tenant: seals defenses and evaluates target output. Never calls Ollama directly."""
import os

import httpx
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import Base, SessionLocal, engine
from internal import GATEWAY_TOKEN, auth_headers, require_eval, require_internal
from keys import key_for
from models import Payload
from policy import heuristic_score_reply, normalize_judge_result

TEAM = "blue"
TEAM_SECRET = os.getenv("BAYORA_BLUE_SECRET", "")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://model-gateway:8003")

Base.metadata.create_all(engine)
app = FastAPI(title="Bayora blue worker")


def db() -> Session:
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


class SealIn(BaseModel):
    test_id: str
    content: str


class OpenIn(BaseModel):
    test_id: str
    ciphertext: str


class EvaluateIn(BaseModel):
    test_id: str
    attack: str = Field(default="", max_length=12000)
    reply: str = Field(max_length=20000)


@app.post("/seal")
def seal(body: SealIn, _: None = Depends(require_internal)):
    f = Fernet(key_for(body.test_id, TEAM, TEAM_SECRET))
    return {"ciphertext": f.encrypt(body.content.encode()).decode(), "team": TEAM}


@app.post("/open")
def open_payload(body: OpenIn, _: None = Depends(require_internal)):
    try:
        f = Fernet(key_for(body.test_id, TEAM, TEAM_SECRET))
        return {"content": f.decrypt(body.ciphertext.encode()).decode(), "team": TEAM}
    except Exception:
        raise HTTPException(400, "blue worker cannot decrypt this ciphertext")


@app.post("/evaluate")
def evaluate(body: EvaluateIn, s: Session = Depends(db), _: None = Depends(require_eval)):
    rows = (s.query(Payload).filter_by(test_id=body.test_id, team=TEAM)
            .order_by(Payload.id).all())
    f = Fernet(key_for(body.test_id, TEAM, TEAM_SECRET))
    texts = []
    for row in rows:
        try:
            texts.append(f.decrypt(row.ciphertext.encode()).decode())
        except Exception:
            continue

    try:
        response = httpx.post(
            f"{GATEWAY_URL}/judge",
            json={"test_id": body.test_id, "attack": body.attack,
                  "reply": body.reply, "blue_criteria": texts},
            headers=auth_headers(GATEWAY_TOKEN),
            timeout=150,
        )
        response.raise_for_status()
        payload = response.json()
        finding = normalize_judge_result(payload["judgment"], body.reply, texts)
        finding["judge_model"] = payload.get("judge_model")
        finding["judge_runner"] = payload.get("judge_runner", "ollama")
        return finding
    except (httpx.HTTPError, KeyError, ValueError, TypeError):
        # Clearly label fallback; never pretend a heuristic result is an LLM judgment.
        finding = heuristic_score_reply(body.reply, texts)
        finding["evaluation_warning"] = "LLM judge unavailable or returned invalid data; heuristic fallback used. Treat this result as inconclusive pending review."
        # Prevent fallback from overclaiming success/defense.
        finding["result"] = "benign_or_unclear"
        finding["confidence"] = 0.0
        return finding


@app.get("/health")
def health():
    return {"ok": True, "role": "blue-worker"}
