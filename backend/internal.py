import hmac
import os

from fastapi import Header, HTTPException

INTERNAL_TOKEN = os.getenv("BAYORA_INTERNAL_TOKEN", "")
EVAL_TOKEN = os.getenv("BAYORA_EVAL_TOKEN", "")
GATEWAY_TOKEN = os.getenv("BAYORA_GATEWAY_TOKEN", "")


def _require(expected: str, provided: str | None, label: str) -> None:
    if not expected or not provided:
        raise HTTPException(401, f"{label} token required")
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(403, f"invalid {label} token")


def require_internal(x_internal_token: str | None = Header(default=None)) -> None:
    _require(INTERNAL_TOKEN, x_internal_token, "internal")


def require_eval(x_internal_token: str | None = Header(default=None)) -> None:
    _require(EVAL_TOKEN, x_internal_token, "eval")


def require_gateway(x_internal_token: str | None = Header(default=None)) -> None:
    _require(GATEWAY_TOKEN, x_internal_token, "gateway")


def auth_headers(token: str) -> dict[str, str]:
    return {"X-Internal-Token": token, "Content-Type": "application/json"}
