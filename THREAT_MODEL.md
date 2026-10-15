# Bayora PoC — Threat Model

This document states what the architecture **protects**, what it **does not**, when guarantees **fail**, and what would be required next. It is written against the **current** proof of concept, not a future production system.

Evaluation objective 06: quantify residual risk.

## 1. System and assets

Logical tenants on one Docker Compose stack:

| Tenant / component | Role |
| --- | --- |
| Red worker | Seals/decrypts **red** artifacts; drives execute |
| Blue worker | Seals/decrypts **blue** artifacts; post-filters model output |
| Model gateway | Only process that calls Ollama |
| Backend API | Broker: auth, ledger, routing — no team secrets, no Ollama |
| Client LLM (Ollama) | Model under test |
| Postgres | Ciphertext + audit ledger |
| Frontend | Operator UI |

**Assets to protect**

- Red-team payloads before the test concludes
- Blue-team defensive logic before the test concludes
- Model weights / KV-cache / in-flight prompts (must not leak across tenants)
- Evaluation findings (integrity: a finding must still be reconstructable)
- Capability tokens and secrets (`BAYORA_RED_SECRET`, `BAYORA_BLUE_SECRET`, worker tokens, ledger Ed25519 private key, DB password)

**Intended security properties (PoC)**

1. Blue cannot **read** red plaintext until conclude (and vice versa).
2. Neither team can call Ollama directly; only **model-gateway** is on the `llm` network with Ollama.
3. Postgres is on an **internal** `data` network; the UI cannot resolve `db` or `ollama`.
4. Every create / upload / execute / conclude / denied-read is appended to a SHA-256 hash chain signed with Ed25519. A verifier needs only the public key.
5. Backend/workers/gateway drop capabilities, use `no-new-privileges`, and a non-root user (Docker default seccomp; custom allowlist withdrawn — see §5.9).
6. Inference is serialized; the Ollama runner is unloaded when the evaluation id changes so tests do not share a live KV-cache (best-effort; see §5.4).

## 2. Trust boundaries

```
[browser / judges]
        |  published :5173 / :8000
        v
   frontend  ----edge---->  backend (broker)
                              |
                           tenants (internal)
                     /        |         \
              red-worker  blue-worker  model-gateway
                     \        |         /
                      data              llm
                       v                 v
                    postgres           ollama
```

- **edge**: UI and broker API. Host ports are published here.
- **tenants**: broker ↔ workers ↔ gateway RPC. `internal: true`. Not on the host.
- **data**: Postgres plus broker/workers that persist ciphertext. `internal: true`.
- **llm**: Ollama plus **model-gateway only**. **Not** `internal` so the image can pull models.

The broker is still an **orchestration TCB** (it holds both workers’ inbound tokens, so it can ask each worker to `/open`). It does **not** hold `BAYORA_RED_SECRET` / `BAYORA_BLUE_SECRET` and does not call Ollama. A memory dump of red-worker cannot decrypt blue rows.

## 3. Attacker model

| Attacker | Assumed power | Goal |
| --- | --- | --- |
| Honest-but-curious red or blue | Valid team token for one test; UI + published API | See the other team’s artifacts before conclude; bias the finding |
| Compromised frontend container | Code on `edge` only | Reach Postgres or Ollama; steal tokens from the page |
| Network neighbor on the Docker host | Can attach to bridges / hit published ports | Hit Ollama or Postgres; sniff |
| Malicious prompt (red) | Content of the attack string | Exfiltrate blue guardrails via model output; contaminate later sessions |
| Operator with Compose env | Reads `docker-compose.yml` | Full compromise (in scope as “trusted operator”) |

Out of scope for this PoC: hypervisor escape, malicious Docker daemon, physical host admin, nation-state covert channels below the container runtime.

## 4. What this architecture protects against

| Threat | Control | Guarantee level |
| --- | --- | --- |
| Blue `GET` of red payloads while status is `open` | Capability token + skip-other-team rows; event `ACCESS_DENIED` | **Enforced** for the HTTP API |
| Frontend → Postgres or Ollama | Network membership; db has no published ports | **Enforced** if Compose file is used as-is (see `scripts/network-isolation.sh`) |
| Red/blue → Ollama without the gateway | Workers not on `llm`; Ollama has no host port | **Enforced** for default Compose |
| Accidental DB dump of payloads | Fernet ciphertext; key = SHA-256(team secret ‖ `test_id` ‖ team) | **Confidentiality vs stolen DB rows**; red secret does not open blue rows |
| Silent rewrite of a ledger row | SHA-256 chain + Ed25519 over canonical JSON | **Detection**, not prevention; verifier uses the **public** key (`scripts/verify_ledger.py`) |
| Backend privilege escalation via extra Linux caps | `cap_drop: ALL`, `no-new-privileges`, non-root UID | **Hardening**, not a formal sandbox proof |
| Unbounded CPU/RAM on db/backend/ollama | Compose `mem_limit` / `cpus` | **Coarse fairness**, not per-test isolation |
| Anonymous minting of tests / listing all evals / global stats | `X-Operator-Token` on create, list, issue; stats scoped to the calling test unless operator | **Enforced** if the demo operator secret is changed |
| Both team tokens in one HTTP response | Separate one-shot `POST /tests/{id}/tokens` per team | **Enforced** for the API; operator can still issue sequentially |
| Two tests sharing Ollama prompt state | Serialize generate; unload model (`keep_alive: 0`) on test switch | **Best-effort** on one runner; not a separate Ollama per test |

## 5. What it does not protect against (residual risk)

These are known gaps. A finding can be **invalidated** by them; we do not claim otherwise.

### 5.1 Broker is still an orchestration TCB

Red, blue, and the model are **separate processes** with separate sealing secrets and inbound tokens. A dump of red-worker yields red plaintext in RAM and `BAYORA_RED_SECRET`, not blue’s secret. Residual: the broker holds **both** `RED_INTERNAL_TOKEN` and `BLUE_INTERNAL_TOKEN`, so a compromised broker can invoke `/open` on both workers. Team capability tokens are stored in Postgres (`capabilities`) so auth survives a broker restart; a stolen DB therefore includes those tokens (not Fernet secrets). The operator cannot re-display a token after it has been issued.

### 5.2 Operator can still issue both tokens in sequence

`POST /tests` returns only `test_id`. Each `POST /tests/{id}/tokens` returns **one** team token and will not show that team again (`409`). The UI keeps at most one revealed token. Residual risk: an operator who issues red, copies it, then issues blue has held both over time. That is the handoff job; it is not a dual-token JSON blob. Team join still uses a single pasted token.

### 5.3 Outcome labels still weakly infer defenses

Blue policy is a **post-generation filter** in blue-worker. Raw guardrail text is **not** concatenated into the model prompt, so the model cannot be induced to echo `<guardrails>`. The ledger stores a SHA-256 of the isolated reply and a `policy_echo_blocked` bit. Residual: red still sees `defended` vs `jailbreak_success`. Keyword heuristics on the reply are not a real safety classifier. Red-worker still sees the raw reply in memory long enough to send it to `/evaluate`; that reply is not returned to the broker or UI.

### 5.4 LLM-native / shared inference

**model-gateway** is the only Ollama client. Isolation is still **one GPU runner**, plus session hygiene:

- Generates are **serialized**; no prior `context` tokens.
- When `test_id` changes, the gateway **unloads** the model (`keep_alive: 0`).
- `BAYORA_FLUSH_EVERY_CALL=1` unloads after every generate.

**Residual:** unload is an Ollama API, not a hardware wipe. One Ollama serves all tests. Gateway compromise sees red prompts. Concurrent tests **queue**. Mock fallback is not a measurement of the client LLM.

### 5.5 Host-published API and demo operator secret

- `POST /tests`, `GET /tests`, and token-issue require `X-Operator-Token`.
- `GET /stats` requires the operator token (global) or a team token (that test only).
- CORS is allowlisted to `http://localhost:5173` and `http://127.0.0.1:5173` (override with `BAYORA_CORS_ORIGINS`).
- Residual: demo default `BAYORA_OPERATOR_TOKEN=dev-operator-change-me` is in Compose and prefilled in the UI. Backend port `8000` is still published on the host, so the UI is not the only client.

### 5.6 Secrets handling

Compose embeds `POSTGRES_PASSWORD=bayora`, per-team sealing secrets, and demo worker tokens. The ledger signing key is generated into a Compose volume (`ledgerkey`) on first boot if unset. Leaking `BAYORA_RED_SECRET` decrypts every **red** row, not blue. Demo-only; change them for anything real.

### 5.7 Audit integrity vs confidentiality

Judges reconstruct the chain **without** a shared HMAC secret:

- `GET /tests/{id}/ledger` returns **full** SHA-256 hashes, prev hashes, and Ed25519 signatures.
- Event **bodies** (canonical JSON) stay redacted until conclude, then `GET .../ledger/export` is the replay package.
- `python scripts/verify_ledger.py export.json` checks hash-link + signature with `public_key_hex` only.
- FINDING rows store labels and `reply_sha256`, not attack text or model replies.

**Residual:** this is still **detect-tamper**, not WORM. Anyone with the **private** key (broker disk/volume, or `BAYORA_LEDGER_PRIVATE_KEY`) can append events that verify. There is no Merkle checkpoint, timestamping authority, or third-party log. If the volume is wiped, a new key is generated and old rows will not verify. HMAC-SHA256 is no longer used.

### 5.8 Side channels

Red and blue no longer share a Python runtime (separate containers, separate cgroup `mem_limit` / `cpus`). They still share one Postgres and one GPU. Timing of `execute` can encode “defended vs not.” Limits are **per service**, not per test. I/O and cache side channels are **unmitigated**.

### 5.9 Container surface

`cap_drop: ALL` and `no-new-privileges` apply to broker/workers/gateway. Frontend (nginx), Postgres, and Ollama run with image defaults (often root). A custom seccomp allowlist (`backend/seccomp-bayora.json`) was tried and **withdrawn**: on Docker Desktop 29 it aborted the process during netns setup, so the demo stack would not start. We therefore use **Docker’s default seccomp**, which still blocks many dangerous syscalls, plus cap-drop. Filesystems are not `read_only`. Rootless Docker/Podman is not enabled in this demo. This is not gVisor/Firecracker; a container breakout is outside the PoC claim but also not demonstrated as prevented.

### 5.10 `llm` network egress

The `llm` bridge is not `internal`, so Ollama can reach the internet to pull weights. A compromised Ollama or model-gateway could exfiltrate prompts. We rely on “only model-gateway is attached,” not on an egress allowlist. Worker ports are unpublished; `scripts/network-isolation.sh` checks UI and workers cannot resolve Ollama.

## 6. When guarantees fail

| Condition | What breaks |
| --- | --- |
| Operator issues both tokens in sequence and pastes both into one brain | Confidentiality still depends on not sharing the second token |
| `BAYORA_RED_SECRET` leaked | All red rows decryptable; blue rows are not |
| Ledger Ed25519 private key leaked or volume reset | Attacker can forge events that still verify; or old events fail to verify |
| Broker compromised | Can `/open` both workers (holds both inbound tokens); cannot talk to Ollama itself |
| Red-worker compromised | Red plaintext + model replies in RAM; cannot decrypt blue or call `/open` on blue |
| Compose networks flattened to one bridge | Frontend can reach db/Ollama; isolation script fails |
| Ollama down and mock path used | Findings are **not** measurements of the client LLM |
| Two tests overlap on the same Ollama | Queued, not parallel; KV-cache is flushed on test switch if unload succeeds. Contamination remains if unload is ignored or a second client hits Ollama. |
| Test already `concluded` | Mutual payload read is **intended**; isolation no longer applies |

## 7. Validity of safety findings

A finding from this PoC is a **demo of the control loop** (seal → execute → ledger), not a production-grade safety result, unless:

- the real Ollama model was used (not the mock fallback),
- blue text was never in the model prompt, and execute returned no `reply_excerpt`,
- generates were serialized and the runner was unloaded between tests (`inference.kv_cache_flushed` true, `runner` is `ollama` not `mock`),
- the ledger `chain_valid` is true under the exported public key (`scripts/verify_ledger.py`).

Keyword heuristics (`bomb`, `jailbreak`, …) are **not** a safety classifier.

## 8. Future improvements (priority if more time)

1. Stop publishing the API to the host if the UI is enough; rotate demo secrets; Postgres RLS so workers cannot SELECT the other team’s ciphertext.
2. Read-only rootfs, pids limits, rootless engine; tighten seccomp; extend hardening to frontend/db/Ollama.
3. Per-test cgroups and constant-size / jittered execute responses against timing side channels.
4. One Ollama (or VM) per evaluation if KV-cache isolation must be hardware-backed.
5. Timestamped / Merkle checkpoints so a stolen private key cannot rewrite history unnoticed.

## 9. One-sentence claim

**We prevent casual cross-team HTTP reads and direct tenant access to Postgres/Ollama on the default Compose networks. Red, blue, and the model are separate containers with separate sealing secrets; the broker does not decrypt artifacts or call Ollama. Blue policy is applied to the reply, not stuffed into the prompt. Inference is serialized and the runner is unloaded when the test id changes. We detect ledger tampering with Ed25519 so a judge verifies without a shared HMAC secret. We do not prevent a broker that holds both worker tokens, someone who holds the ledger private key, KV-cache that survives a failed unload, timing side channels, or inferring that a defense fired from the `defended` label.**
