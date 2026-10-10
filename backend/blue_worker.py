"""Blue tenant: seals defenses and scores model output. Never talks to Ollama."""

import os

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import Base, SessionLocal, engine
from internal import require_eval, require_internal
from keys import key_for
from models import Payload
from policy import score_reply

TEAM = "blue"
TEAM_SECRET = os.getenv("BAYORA_BLUE_SECRET", "")

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
    reply: str


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
    rows = (
        s.query(Payload)
        .filter_by(test_id=body.test_id, team=TEAM)
        .order_by(Payload.id)
        .all()
    )
    f = Fernet(key_for(body.test_id, TEAM, TEAM_SECRET))
    texts = []
    for row in rows:
        try:
            texts.append(f.decrypt(row.ciphertext.encode()).decode())
        except Exception:
            continue
    scored = score_reply(body.reply, texts)
    # Never return defense plaintext or the raw reply.
    return scored


@app.get("/health")
def health():
    return {"ok": True, "role": "blue-worker"}
