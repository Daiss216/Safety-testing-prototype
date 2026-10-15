# Bayora — Track 04 (secure adversarial AI testing)

Red, blue, and the model are **separate containers**. The FastAPI **backend is a broker**: it never decrypts tenant artifacts and never talks to Ollama. One browser session holds **one** team token.

Threat model and residual risk: [THREAT_MODEL.md](THREAT_MODEL.md).

## Architecture

```
browser :5173  --edge-->  frontend (nginx)
browser :8000  --edge-->  backend (broker, ledger, tokens)
                              |
                         tenants (internal)
              red-worker   blue-worker   model-gateway
                     \         |               |
                   data (int.) |              llm
                       postgres            ollama
```

- `data` and `tenants` are `internal: true`.
- `llm` is **not** internal so Ollama can pull weights. Only `model-gateway` is attached with it.
- Worker and gateway ports are **not** published.

## Run

Copy [docker-compose.yml](docker-compose.yml) secrets before anything real. Demo defaults are intentional and documented as residual risk.

```bash
docker compose up -d --build
# first boot: ollama-pull fetches llama3.2:3b (findings use the mock path until that finishes)
./scripts/network-isolation.sh
./scripts/demo-flow.sh          # API proof of isolation
```

UI: http://localhost:5173  
API: http://localhost:8000 (published so the browser can call it; CORS allowlist is localhost:5173)

## What to click (isolation demo)

1. Operator token is prefilled (`dev-operator-change-me`). Click **+ New Evaluation**.
2. **Issue RED token** → copy it. Do **not** issue blue yet (the page never keeps two tokens).
3. **Enter RED console**. Seal & upload an attack. **Read Payloads** — only red rows. **Execute Attack vs LLM** — labels + `reply_sha256`, no model text, no blue guardrails.
4. **Leave console** (handoff for that test comes back). Issue **BLUE token**, enter blue console (or open another browser profile and **Join** as blue with the copied token).
5. Blue **Read Payloads** — cannot see red. Upload a defense. Blue **cannot** Execute (403, ledger `ACCESS_DENIED`).
6. Either team **Conclude Test**. **Read Payloads** now returns both sides. **Verify Audit Ledger** (full hashes + Ed25519). **Export ledger** and:

```bash
python scripts/verify_ledger.py bayora-ledger-<id>.json
```

Verifier needs the **public** key in the export, not a shared HMAC secret.

Team tokens persist in Postgres so a broker restart does not wipe auth for an open test. The operator still cannot re-display an already-issued token (`409`).

## Isolation checks

| Check | Expected |
| --- | --- |
| Blue GET payloads while open | Own rows only; `ACCESS_DENIED` in ledger |
| Execute as blue | 403 |
| Execute response | No `reply` / `reply_excerpt` |
| Ledger while open | Full hashes, **bodies redacted** |
| Export before conclude | 409 |
| `scripts/network-isolation.sh` | Frontend cannot resolve db / ollama / workers |

## Residual (honest)

HMAC is **not** used for reconstruction — Ed25519 is. Team tokens are in Postgres (a DB dump of `capabilities` is residual). Demo secrets are in Compose. Custom seccomp is not applied (it prevented containers from starting on Docker Desktop 29). Shared Ollama KV-cache residual: see threat model.
