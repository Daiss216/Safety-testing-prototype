"""Tamper-evident audit trail.

Each event is a SHA-256 hash chain over canonical JSON, signed with Ed25519.
A third party verifies with the public key only — they do not need a shared
HMAC secret. Detection, not prevention: anyone with the private key can append
events that still verify.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS = "0" * 64
ALG = "Ed25519"


def _load_private() -> Ed25519PrivateKey:
    pem_env = os.getenv("BAYORA_LEDGER_PRIVATE_KEY")
    if pem_env:
        raw = pem_env.replace("\\n", "\n").encode()
        return serialization.load_pem_private_key(raw, password=None)
    path = Path(os.getenv("BAYORA_LEDGER_KEY_PATH", "ledger_ed25519.pem"))
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pem)
        path.with_name(path.stem + "_public.pem").write_bytes(pub)
    except OSError:
        pass
    return key


_PRIVATE = _load_private()
_PUBLIC = _PRIVATE.public_key()


def public_key_hex() -> str:
    return _PUBLIC.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def public_key_pem() -> str:
    return _PUBLIC.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def make_entry(prev_hash: str, event_type: str, data: dict):
    """Build one ledger entry. Returns (hash, signature_hex, ts, canonical_body)."""
    ts = time.time()
    body = json.dumps(
        {"prev": prev_hash, "type": event_type, "data": data, "ts": ts},
        sort_keys=True,
    )
    encoded = body.encode()
    h = hashlib.sha256(encoded).hexdigest()
    sig = _PRIVATE.sign(encoded).hex()
    return h, sig, ts, body


def verify_body(
    body: str,
    expected_hash: str,
    expected_sig: str,
    public_hex: str | None = None,
) -> bool:
    h = hashlib.sha256(body.encode()).hexdigest()
    if h != expected_hash:
        return False
    try:
        if public_hex:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        else:
            pub = _PUBLIC
        pub.verify(bytes.fromhex(expected_sig), body.encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_chain(events: list[dict], public_hex: str | None = None) -> bool:
    """Replay a full export. Each item needs prev_hash, hash, signature, body."""
    prev = GENESIS
    key = public_hex or public_key_hex()
    for ev in events:
        if ev.get("prev_hash") != prev:
            return False
        if not verify_body(ev["body"], ev["hash"], ev["signature"], key):
            return False
        prev = ev["hash"]
    return True


def finding_for_ledger(finding: dict) -> dict:
    """Store labels and artifact hashes only — never attack text or model replies."""
    inference = finding.get("inference") or {}
    return {
        "payload_id": finding.get("payload_id"),
        "result": finding.get("result"),
        "refused": finding.get("refused"),
        "sensitive_leak": finding.get("sensitive_leak"),
        "defense_count": finding.get("defense_count"),
        "reply_sha256": finding.get("reply_sha256"),
        "policy_echo_blocked": finding.get("policy_echo_blocked"),
        "output_isolated": finding.get("output_isolated"),
        "policy_engine": finding.get("policy_engine"),
        "model": finding.get("model") or inference.get("model"),
        "inference": {
            "session": inference.get("session"),
            "serialized": inference.get("serialized"),
            "kv_cache_flushed": inference.get("kv_cache_flushed"),
            "runner": inference.get("runner"),
        },
    }
