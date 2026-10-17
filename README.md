# Bayora — Secure Adversarial AI Safety Testing Platform

Bayora is a proof-of-concept platform for **red vs. blue** evaluation of LLM safety: red team submits attack prompts, blue team submits defenses, payloads stay **encrypted and team-isolated** until a test concludes, the backend alone talks to the **client LLM (Ollama)**, and every action is recorded in a **hash-chained, HMAC-signed audit ledger**.

> **Status:** Proof of concept (PoC). Do not treat this implementation as production-grade security without further review and testing.
## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#structure)
- [Technology Stack](#technology-stack)
- [Run with Docker Compose](#run-with-docker)
- [Run Locally](#local-dev)
- [Features](#features)
- [API Overview](#api-overview)
- [Workflow](#demo-workflow)

## Overview

Bayora aims to provide a controlled environment in which:

- **Red Team** submits adversarial prompts to test an LLM.
- **Blue Team** submits defensive policies and evaluates model responses.
- **Model Gateway** mediates requests to the model service.
- **Backend/Broker** coordinates evaluations and enforces API access rules.
- **Audit Ledger** records evaluation events and supports integrity verification.

The goal is to reduce unauthorized cross-team access and make testing activity easier to inspect and reproduce.

## Architecture

```
┌─────────────┐     HTTP :8000      ┌──────────────┐     internal      ┌─────────┐
│  React UI   │ ──────────────────► │   FastAPI    │ ────────────────► │ Ollama  │
│  :5173      │   X-Token per team  │   backend    │                   │ :11434  │
└─────────────┘                     └──────┬───────┘                   └─────────┘
                                           │
                                           ▼
                                    PostgreSQL or SQLite
```

## Structure
```bash
Bayora
├── docker-compose.yml              # Multi-container local deployment
├── README.md                       # Project documentation
├── THREAT_MODEL.md                 # Threats, assumptions, and residual risks
├── .gitignore                      # Files excluded from version control
│
├── backend/
│   ├── Dockerfile                  # Backend/worker container image
│   ├── requirements.txt            # Python dependencies
│   ├── main.py                     # FastAPI broker and API endpoints
│   ├── audit.py                    # Hash-chained audit entries and verification helpers
│   ├── models.py                   # SQLAlchemy database models
│   ├── database.py                 # Database engine and session setup
│   ├── internal.py                 # Internal worker authentication helpers
│   ├── keys.py                     # Team/test encryption key helpers
│   ├── red_worker.py               # Red-team payload and execution service
│   ├── blue_worker.py              # Blue-team payload and evaluation service
│   ├── model_gateway.py             # Gateway between workers and Ollama
│   ├── policy.py                   # Model-response evaluation/scoring rules
│   └── seccomp-bayora.json         # Container syscall restrictions
│
├── frontend/
│   ├── Dockerfile                  # Frontend build and web-server image
│   ├── package.json                # JavaScript dependencies and scripts
│   ├── package-lock.json           # Locked npm dependency versions
│   ├── vite.config.js              # Vite configuration
│   ├── tailwind.config.js          # Tailwind CSS configuration
│   ├── postcss.config.js           # PostCSS configuration
│   ├── index.html                  # HTML entry point
│   ├── .env.example                # Example frontend environment configuration
│   └── src/
│       ├── main.jsx                # React application entry point
│       ├── App.jsx                 # Bayora dashboard and API interactions
│       └── index.css               # Global styles and UI component classes
│
└── scripts/
    ├── network-isolation.sh        # Network isolation helper script
    └── verify_ledger.py            # Audit ledger verification utility
```

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Frontend | React, Vite | Interactive dashboard |
| Styling | Tailwind CSS and custom CSS | Sketch-style monochrome interface |
| Charts | Chart.js, `react-chartjs-2` | Findings and outcome visualizations |
| API | Python, FastAPI | Request handling and access control |
| Validation | Pydantic | Request-body validation |
| Database layer | SQLAlchemy | Database models and queries |
| Database | PostgreSQL | Persistent records in Docker deployment |
| Encryption | Fernet | Encryption of stored team payloads |
| Audit integrity | SHA-256 hash chain and HMAC signing (as implemented) | Detect changes to recorded audit entries |
| LLM runtime | Ollama | Runs the model under test |
| Deployment | Docker, Docker Compose | Service packaging and networking |

## Run with Docker
```bash
docker compose up --build
# frontend  -> http://localhost:5173
# backend   -> http://localhost:8000/docs
```
(The Ollama model downloads on first attack run; without it the backend
uses a deterministic mock so the demo always works.)

## Local dev
```bash
# backend
cd backend && pip install -r requirements.txt && uvicorn main:app --reload
# frontend (new terminal)
cd frontend && npm install && npm run dev
```
Falls back to SQLite when DATABASE_URL is unset.

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

## Demo workflow

1. Click **+ New Evaluation** — save the red and blue tokens (shown once).
2. Select **RED TEAM**, paste a jailbreak-style prompt, **Seal & Upload**.
3. **Execute Attack vs LLM** — inspect the JSON finding.
4. Switch to **BLUE TEAM**, upload a defensive note (sealed separately).
5. As red, **Read Payloads** — blue content stays hidden until conclusion.
6. **Conclude Test**, then read payloads as blue to confirm isolation lifted.
7. **Verify Audit Ledger** — confirm `chain_valid: true`.
8. Watch **Findings Overview** charts update after executions.
