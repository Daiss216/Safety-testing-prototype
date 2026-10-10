#!/usr/bin/env python3
"""Replay a Bayora ledger export with the Ed25519 public key only.

Does not need BAYORA_LEDGER_SECRET, the private key, or the running API.

    python scripts/verify_ledger.py path/to/export.json

Export JSON comes from GET /tests/{id}/ledger/export after conclude.
Requires: cryptography
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GENESIS = "0" * 64


def fail(msg: str) -> int:
    print(f"INVALID: {msg}")
    return 1


def verify(doc: dict) -> int:
    alg = doc.get("algorithm")
    if alg != "Ed25519":
        return fail(f"unsupported algorithm {alg!r}")
    key_hex = doc.get("public_key_hex") or ""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
    except ValueError:
        return fail("public_key_hex is not a 32-byte Ed25519 key")

    prev = GENESIS
    events = doc.get("events") or []
    if not events:
        return fail("no events")
    if events[0].get("prev_hash") != GENESIS:
        return fail("first prev_hash is not genesis")

    for i, ev in enumerate(events):
        body = ev.get("body")
        if body is None:
            return fail(
                f"event {i} has no body (export is only available after conclude)"
            )
        digest = hashlib.sha256(body.encode()).hexdigest()
        if digest != ev.get("hash"):
            return fail(f"event {i} hash mismatch")
        if ev.get("prev_hash") != prev:
            return fail(f"event {i} broken chain (prev_hash)")
        try:
            pub.verify(bytes.fromhex(ev["signature"]), body.encode())
        except (InvalidSignature, ValueError, KeyError):
            return fail(f"event {i} Ed25519 signature rejected")
        prev = ev["hash"]

    print("VALID")
    print(f"  algorithm     {alg}")
    print(f"  public_key    {key_hex}")
    print(f"  test_id       {doc.get('test_id')}")
    print(f"  events        {len(events)}")
    print(f"  tip           {prev}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python scripts/verify_ledger.py export.json", file=sys.stderr)
        return 2
    path = Path(argv[1])
    doc = json.loads(path.read_text())
    return verify(doc)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
