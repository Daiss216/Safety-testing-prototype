"""
Bayora broker: auth, ledger, and routing. It does not decrypt tenant artifacts
and it does not call Ollama. Red, blue, and the model each have their own process.
"""

import hmac
import json
import os
import time
import uuid

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Literal

from pydantic import BaseModel
from sqlalchemy.orm import Session

from audit import GENESIS, make_entry, verify_body
from database import Base, engine, SessionLocal
from internal import auth_headers
from models import Ledger, Payload, Test

from dotenv import load_dotenv

load_dotenv()

OPERATOR_TOKEN = os.getenv("BAYORA_OPERATOR_TOKEN", "dev-operator-change-me")
RED_WORKER_URL = os.getenv("RED_WORKER_URL", "http://red-worker:8001")
BLUE_WORKER_URL = os.getenv("BLUE_WORKER_URL", "http://blue-worker:8002")
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "BAYORA_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if o.strip()
]

Base.metadata.create_all(engine)

app = FastAPI(title="Bayora - Secure Adversarial AI Testing")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Token", "X-Operator-Token"],
)

TOKENS: dict[str, dict[str, str]] = {}
ISSUED: dict[str, set[str]] = {}
WORKERS = {"red": RED_WORKER_URL, "blue": BLUE_WORKER_URL}
WORKER_TOKENS = {
    "red": os.getenv("RED_INTERNAL_TOKEN", ""),
    "blue": os.getenv("BLUE_INTERNAL_TOKEN", ""),
}


def db() -> Session:
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def operator_ok(header: str | None) -> bool:
    if not OPERATOR_TOKEN or not header:
        return False
    return hmac.compare_digest(header, OPERATOR_TOKEN)


def require_operator(x_operator_token: str | None = Header(default=None)) -> None:
    if not operator_ok(x_operator_token):
        raise HTTPException(401, "valid X-Operator-Token required")


def test_id_of_token(token: str | None) -> str:
    if not token:
        raise HTTPException(401, "missing token")
    for test_id, teams in TOKENS.items():
        for tok in teams.values():
            if hmac.compare_digest(tok, token):
                return test_id
    raise HTTPException(401, "invalid token")


def team_of(test_id: str, token: str | None) -> str:
    t = TOKENS.get(test_id)
    if not t:
        raise HTTPException(401, "unknown test id")
    for team, tok in t.items():
        if token and hmac.compare_digest(tok, token):
            return team
    raise HTTPException(403, "invalid token")


def get_test(test_id: str, s: Session) -> Test:
    t = s.get(Test, test_id)
    if not t:
        raise HTTPException(404, "test not found")
    return t


def require_open(test: Test, s: Session, team: str, action: str) -> None:
    if test.status != "concluded":
        return
    log(s, test.id, "ACCESS_DENIED", {
        "team": team, "reason": f"cannot {action} after test conclusion",
    })
    s.commit()
    raise HTTPException(409, "This test is concluded; uploads and attacks are closed.")


def log(s: Session, test_id: str, event_type: str, data: dict):
    last = (
        s.query(Ledger).filter_by(test_id=test_id).order_by(Ledger.id.desc()).first()
    )
    prev = last.hash if last else GENESIS
    h, sig, ts, body = make_entry(prev, event_type, data)
    s.add(
        Ledger(
            test_id=test_id, prev_hash=prev, hash=h, event_type=event_type,
            data=body, signature=sig, ts=ts,
        )
    )


def worker_post(team: str, path: str, payload: dict, timeout: float = 30.0) -> dict:
    token = WORKER_TOKENS[team]
    if not token:
        raise HTTPException(500, f"{team} worker token is not set")
    url = f"{WORKERS[team]}{path}"
    try:
        r = httpx.post(url, json=payload, headers=auth_headers(token), timeout=timeout)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text
        try:
            detail = exc.response.json().get("detail", detail)
        except Exception:
            pass
        raise HTTPException(exc.response.status_code, detail) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"{team} worker unreachable: {exc}") from exc


class CreateTestIn(BaseModel):
    name: str


class PayloadIn(BaseModel):
    content: str


class IssueTokenIn(BaseModel):
    team: Literal["red", "blue"]


@app.post("/tests")
def create_test(
    body: CreateTestIn,
    s: Session = Depends(db),
    _: None = Depends(require_operator),
):
    test_id = uuid.uuid4().hex[:12]
    TOKENS[test_id] = {"red": uuid.uuid4().hex, "blue": uuid.uuid4().hex}
    ISSUED[test_id] = set()
    h, sig, ts, raw = make_entry(GENESIS, "TEST_CREATED", {"name": body.name})
    s.add(Test(id=test_id, name=body.name, created_at=ts, genesis_hash=h))
    s.add(Ledger(
        test_id=test_id, prev_hash=GENESIS, hash=h, event_type="TEST_CREATED",
        data=raw, signature=sig, ts=ts,
    ))
    s.commit()
    return {
        "test_id": test_id,
        "note": "Issue red and blue tokens separately via POST /tests/{id}/tokens. This response has neither.",
    }


@app.post("/tests/{test_id}/tokens")
def issue_team_token(
    test_id: str,
    body: IssueTokenIn,
    s: Session = Depends(db),
    _: None = Depends(require_operator),
):
    get_test(test_id, s)
    if test_id not in TOKENS:
        raise HTTPException(401, "unknown test id")
    issued = ISSUED.setdefault(test_id, set())
    if body.team in issued:
        raise HTTPException(409, f"{body.team} token already issued; server will not show it again")
    issued.add(body.team)
    log(s, test_id, "TOKEN_ISSUED", {"team": body.team})
    s.commit()
    return {
        "test_id": test_id,
        "team": body.team,
        "token": TOKENS[test_id][body.team],
        "note": "Copy this token to that team only. The other team's token is not in this response.",
    }


@app.post("/tests/{test_id}/payloads")
def upload_payload(
    test_id: str, body: PayloadIn,
    x_token: str = Header(None), s: Session = Depends(db),
):
    team = team_of(test_id, x_token)
    test = get_test(test_id, s)
    require_open(test, s, team, "upload payloads")
    sealed = worker_post(team, "/seal", {"test_id": test_id, "content": body.content})
    p = Payload(test_id=test_id, team=team, ciphertext=sealed["ciphertext"])
    s.add(p)
    s.flush()
    log(s, test_id, "PAYLOAD_UPLOADED", {"by": team, "payload_id": p.id})
    s.commit()
    return {"payload_id": p.id, "sealed": True, "visible_to_other_team": "only after conclusion"}


@app.get("/tests/{test_id}/payloads")
def read_payloads(
    test_id: str, x_token: str = Header(None), s: Session = Depends(db),
):
    team = team_of(test_id, x_token)
    test = get_test(test_id, s)
    concluded = test.status == "concluded"
    rows = s.query(Payload).filter_by(test_id=test_id).all()
    out = []
    sealed_from_other = 0
    for r in rows:
        if r.team != team and not concluded:
            sealed_from_other += 1
            continue
        opened = worker_post(r.team, "/open", {
            "test_id": test_id, "ciphertext": r.ciphertext,
        })
        out.append({
            "payload_id": r.id,
            "team": r.team,
            "content": opened["content"],
        })
    if sealed_from_other:
        log(s, test_id, "ACCESS_DENIED", {
            "team": team,
            "reason": "other team's payloads are sealed until test conclusion",
            "sealed_count": sealed_from_other,
        })
    log(s, test_id, "PAYLOADS_READ", {"by": team, "count": len(out)})
    s.commit()
    return {"payloads": out}


@app.post("/tests/{test_id}/execute")
def execute_attack(
    test_id: str, x_token: str = Header(None), s: Session = Depends(db),
):
    """Broker only: red worker decrypts red, gateway infers, blue worker scores."""
    team = team_of(test_id, x_token)
    if team != "red":
        log(s, test_id, "ACCESS_DENIED", {"team": team, "reason": "only red executes attacks"})
        s.commit()
        raise HTTPException(403, "Only the red team can trigger attacks.")
    test = get_test(test_id, s)
    require_open(test, s, team, "execute attacks")
    red = (
        s.query(Payload).filter_by(test_id=test_id, team="red")
        .order_by(Payload.id.desc()).first()
    )
    if not red:
        raise HTTPException(400, "no red payload uploaded yet")
    log(s, test_id, "EXECUTION_STARTED", {"payload_id": red.id, "via": "red-worker"})
    s.commit()
    finding = worker_post("red", "/execute", {"test_id": test_id}, timeout=180.0)
    log(s, test_id, "FINDING", finding)
    s.commit()
    return finding


@app.post("/tests/{test_id}/conclude")
def conclude_test(
    test_id: str, x_token: str = Header(None), s: Session = Depends(db),
):
    team = team_of(test_id, x_token)
    test = get_test(test_id, s)
    if test.status == "concluded":
        raise HTTPException(409, "This test is already concluded.")
    test.status = "concluded"
    log(s, test_id, "TEST_CONCLUDED", {"by": team})
    s.commit()
    return {"test_id": test_id, "status": "concluded",
            "note": "Payloads/defenses are now mutually readable; ledger stays immutable."}


@app.get("/tests/{test_id}/ledger")
def get_ledger(test_id: str, x_token: str = Header(None), s: Session = Depends(db)):
    team_of(test_id, x_token)
    get_test(test_id, s)
    rows = s.query(Ledger).filter_by(test_id=test_id).order_by(Ledger.id).all()
    prev, valid, events = GENESIS, True, []
    for r in rows:
        ok = verify_body(r.data, r.hash, r.signature) and r.prev_hash == prev
        if not ok:
            valid = False
        events.append({
            "seq": r.id, "type": r.event_type, "ts": r.ts,
            "hash": r.hash[:16] + "...", "signature": r.signature[:16] + "...",
            "tampered": not ok,
        })
        prev = r.hash
    return {"test_id": test_id, "chain_valid": valid, "events": events}


@app.get("/tests")
def list_tests(
    s: Session = Depends(db),
    _: None = Depends(require_operator),
):
    return [
        {"test_id": t.id, "name": t.name, "status": t.status, "created_at": t.created_at}
        for t in s.query(Test).all()
    ]


@app.get("/stats")
def stats(
    s: Session = Depends(db),
    x_token: str | None = Header(default=None),
    x_operator_token: str | None = Header(default=None),
):
    if operator_ok(x_operator_token):
        scope_id = None
    else:
        scope_id = test_id_of_token(x_token)
    q = s.query(Ledger).filter_by(event_type="FINDING")
    if scope_id:
        q = q.filter_by(test_id=scope_id)
    rows = q.all()
    per_day, outcomes = {}, {"jailbreak_success": 0, "defended": 0, "benign_or_unclear": 0}
    for r in rows:
        f = json.loads(r.data)["data"]
        day = time.strftime("%Y-%m-%d", time.localtime(r.ts))
        per_day[day] = per_day.get(day, 0) + 1
        outcomes[f["result"]] = outcomes.get(f["result"], 0) + 1
    return {"scope": scope_id or "all", "per_day": per_day, "outcomes": outcomes}
