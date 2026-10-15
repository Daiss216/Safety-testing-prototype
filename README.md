# Bayora — Secure Adversarial AI Safety Testing Infrastructure

Bayora is a proof-of-concept platform for **red vs. blue** evaluation of LLM safety: red team submits attack prompts, blue team submits defenses, payloads stay **encrypted and team-isolated** until a test concludes, the backend alone talks to the **client LLM (Ollama)**, and every action is recorded in a **hash-chained, HMAC-signed audit ledger**.

Shared red-team / blue-team / client-LLM sandbox where:
- attack payloads & defenses are **sealed per-test** (Fernet, per-test key),
- red cannot read blue and **blue cannot read red until the test concludes**,
- the client LLM is reachable **only by the backend** (network isolation),
- every action lands in a **SHA-256 hash-chained, HMAC-signed ledger**.

```
┌─────────────┐     HTTP :8000      ┌──────────────┐     internal      ┌─────────┐
│  React UI   │ ──────────────────► │   FastAPI    │ ────────────────► │ Ollama  │
│  :5173      │   X-Token per team  │   backend    │                   │ :11434  │
└─────────────┘                     └──────┬───────┘                   └─────────┘
                                           │
                                           ▼
                                    PostgreSQL or SQLite
```

---
## Run (Docker, one command)
```bash
docker compose up --build
# frontend  -> http://localhost:5173
# backend   -> http://localhost:8000/docs
```
(The Ollama model downloads on first attack run; without it the backend
uses a deterministic mock so the demo always works.)

## Local dev (no Docker)
```bash
# backend
cd backend && pip install -r requirements.txt && uvicorn main:app --reload
# frontend (new terminal)
cd frontend && npm install && npm run dev
```
Falls back to SQLite when DATABASE_URL is unset.

## Structure
```bash
bayora/
├── docker-compose.yml          # one-command local deployment (all 4 services)
├── README.md                   # run instructions + 2-min judge demo script
│
├── backend/                    # Python FastAPI (the "security brain")
│   ├── Dockerfile              # slim image, runs as non-root user
│   ├── requirements.txt        # Python dependencies
│   ├── main.py                 # all API endpoints + isolation logic
│   ├── audit.py                # SHA-256 hash-chain + HMAC signing
│   ├── models.py               # SQLAlchemy tables (tests, payloads, ledger)
│   ├── database.py             # Postgres engine (SQLite fallback)
│   └── seccomp-bayora.json     # syscall allow-list for container hardening
│
├── frontend/                   # React + Tailwind + Chart.js dashboard
│   ├── Dockerfile              # multi-stage: build → serve via nginx
│   ├── package.json            # npm dependencies
│   ├── vite.config.js          # dev server config
│   ├── tailwind.config.js      # Tailwind setup
│   ├── postcss.config.js       # CSS pipeline
│   ├── index.html              # HTML entry point
│   ├── .env.example            # backend URL config
│   └── src/
│       ├── main.jsx            # React entry
│       ├── App.jsx             # entire dashboard UI (single file)
│       └── index.css           # Tailwind styles + component classes
│
├── scripts/
     └── network-isolation.sh    # iptables deny-by-default tenant segmentation

```
## Features

| Area | What it does |
|------|----------------|
| **Test lifecycle** | Create an evaluation; receive separate **red** and **blue** capability tokens (shown once). |
| **Sealed payloads** | Upload prompts/notes encrypted with a **per-test Fernet key** derived from `BAYORA_SECRET` + `test_id`. |
| **Team isolation** | Red cannot read blue payloads. Blue cannot read red payloads until the test is **concluded**. |
| **Attack execution** | Red team triggers `/execute`; server decrypts in memory, calls Ollama (or a **mock** if Ollama is down), classifies outcome. |
| **Findings heuristics** | Labels: `jailbreak_success`, `defended`, or `benign_or_unclear` using refusal/leak keyword checks (demo logic). |
| **Audit ledger** | Append-only SHA-256 chain + HMAC signatures; UI verifies **chain integrity** and flags tampering. |
| **Dashboard** | Bar chart (findings per day) and doughnut (outcome mix) from `/stats`. |
| **Infrastructure story (Docker)** | Postgres, isolated bridge network, Ollama without a public port, backend seccomp + capability drops (Linux). |

### API overview

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/tests` | — | Create test; returns `test_id`, `red_token`, `blue_token` |
| `POST` | `/tests/{id}/payloads` | `X-Token` | Seal and upload payload |
| `GET` | `/tests/{id}/payloads` | `X-Token` | Read allowed payloads (isolation rules apply) |
| `POST` | `/tests/{id}/execute` | Red token | Run latest red payload against LLM |
| `POST` | `/tests/{id}/conclude` | Any team token | Open mutual read access |
| `GET` | `/tests/{id}/ledger` | `X-Token` | Verify audit chain |
| `GET` | `/tests` | — | List tests |
| `GET` | `/stats` | — | Aggregate findings for charts |

Interactive docs when the API is running: [http://localhost:8000/docs](http://localhost:8000/docs)

## Demo workflow (UI)

1. Click **+ New Evaluation** — save the red and blue tokens (shown once).
2. Select **RED TEAM**, paste a jailbreak-style prompt, **Seal & Upload**.
3. **Execute Attack vs LLM** — inspect the JSON finding.
4. Switch to **BLUE TEAM**, upload a defensive note (sealed separately).
5. As red, **Read Payloads** — blue content stays hidden until conclusion.
6. **Conclude Test**, then read payloads as blue to confirm isolation lifted.
7. **Verify Audit Ledger** — confirm `chain_valid: true`.
8. Watch **Findings Overview** charts update after executions.
