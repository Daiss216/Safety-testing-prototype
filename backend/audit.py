"""Tamper-evident audit trail.

Every evaluation event is appended as a hash-chained, HMAC-signed,
timestamped record. Any modification breaks the chain and is detected
when the ledger is verified."""

import hashlib
import hmac
import json
import os
import time

LEDGER_SECRET = os.getenv("BAYORA_LEDGER_SECRET", "bayora-ledger-secret")
GENESIS = "0" * 64


def make_entry(prev_hash: str, event_type: str, data: dict):
    """Build one ledger entry. Returns (hash, signature, ts, canonical_body)."""
    ts = time.time()
    body = json.dumps(
        {"prev": prev_hash, "type": event_type, "data": data, "ts": ts},
        sort_keys=True,
    )
    h = hashlib.sha256(body.encode()).hexdigest()
    sig = hmac.new(LEDGER_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return h, sig, ts, body


def verify_body(body: str, expected_hash: str, expected_sig: str) -> bool:
    h = hashlib.sha256(body.encode()).hexdigest()
    sig = hmac.new(LEDGER_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(h, expected_hash) and hmac.compare_digest(sig, expected_sig)