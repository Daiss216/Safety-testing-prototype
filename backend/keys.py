import base64
import hashlib


def key_for(test_id: str, team: str, secret: str) -> bytes:
    """Per-test, per-team Fernet key. Red and blue secrets are different, so
    holding one worker's env cannot decrypt the other tenant's rows."""
    if not secret:
        raise ValueError(f"missing sealing secret for team {team}")
    raw = hashlib.sha256(f"{secret}:{test_id}:{team}".encode()).digest()
    return base64.urlsafe_b64encode(raw)
