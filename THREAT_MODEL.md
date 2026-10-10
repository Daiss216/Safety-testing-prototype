# Bayora PoC — Threat Model

This document states what the architecture **protects**, what it **does not**, when guarantees **fail**, and what would be required next. It is written against the **current** proof of concept, not a future production system.

Evaluation objective 06: quantify residual risk.

## 1. System and assets

Logical tenants on one Docker Compose stack:

| Tenant / component | Role |
| --- | --- |
| Red team | Uploads attack payloads; triggers execution |
| Blue team | Uploads defensive guardrails |
| Client LLM (Ollama) | Model under test |
| Backend API | Broker: auth, sealing, execute, ledger |
| Postgres | Encrypted payloads + audit ledger |
| Frontend | Operator UI |

**Assets to protect**

- Red-team payloads before the test concludes
- Blue-team defensive logic before the test concludes
- Model weights / KV-cache / in-flight prompts (must not leak across tenants)
- Evaluation findings (integrity: a finding must still be reconstructable)
- Capability tokens and master secrets (`BAYORA_SECRET`, `BAYORA_LEDGER_SECRET`, DB password)

**Intended security properties (PoC)**

1. Blue cannot **read** red plaintext until conclude (and vice versa).
2. Neither team can call Ollama directly; only the backend is on the `llm` network.
3. Postgres is on an **internal** `data` network; the UI cannot resolve `db` or `ollama`.
4. Every create / upload / execute / conclude / denied-read is appended to a hash-chained, HMAC-signed ledger.
5. Backend process drops capabilities, uses a seccomp profile, `no-new-privileges`, and a non-root user.

## 2. Trust boundaries

```
[browser / judges]
        |  published :5173 / :8000
        v
   frontend  ----edge---->  backend
                              |          |
                           data          llm
                              v          v
                           postgres    ollama
```

- **edge**: UI and API. Host ports are published here.
- **data**: Postgres only; `internal: true` (no internet, no UI).
- **llm**: Ollama only plus backend. **Not** `internal` so the image can pull models. Isolation is **membership**, not a deny-all egress policy.

The backend is a **cross-tenant trusted computing base**. It can decrypt both teams’ artifacts in memory during `POST /tests/{id}/execute`.

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
| Red/blue → Ollama without the broker | Ollama not on `edge`; no host port | **Enforced** for default Compose |
| Accidental DB dump of payloads | Fernet ciphertext; key = SHA-256(`BAYORA_SECRET` ‖ `test_id`) | **Confidentiality vs stolen DB rows**, not vs stolen master secret |
| Silent rewrite of a ledger row | SHA-256 chain + HMAC-SHA256 over canonical JSON | **Detection**, not prevention; verifier needs `BAYORA_LEDGER_SECRET` |
| Backend privilege escalation via extra Linux caps | `cap_drop: ALL`, `no-new-privileges`, non-root UID | **Hardening**, not a formal sandbox proof |
| Unbounded CPU/RAM on db/backend/ollama | Compose `mem_limit` / `cpus` | **Coarse fairness**, not per-test isolation |

## 5. What it does not protect against (residual risk)

These are known gaps. A finding can be **invalidated** by them; we do not claim otherwise.

### 5.1 Shared trusted backend (cross-tenant TCB)

Red, blue, and orchestration share **one FastAPI process**. A bug, debug log, or memory disclosure in that process exposes both teams. Tokens live in **process memory** (`TOKENS`) and vanish on restart (availability), but a live dump yields both teams’ tokens.

### 5.2 Same UI session holds both tokens

`POST /tests` returns `red_token` and `blue_token` together; the dashboard stores both and lets the operator switch teams. That is a **demo convenience**, not tenant isolation. Anyone with the create-test response is both red and blue.

### 5.3 Blue logic inferable from execute

On execute, blue plaintext is concatenated into the prompt (`<guardrails>…`). The JSON finding includes `reply_excerpt` (first 160 characters of the model reply). The model may echo guardrails; red also observes `defended` vs `jailbreak_success`. That **violates** “defensive logic must not be inferable by red-team tooling” in the strong sense.

### 5.4 LLM-native / shared inference

One Ollama instance serves all tests. There is **no** per-test KV-cache isolation, cache flush, or session namespace. Prompt fragments from test A can theoretically remain in GPU/runtime state while test B runs. Cross-session contamination is **unmitigated**.

### 5.5 Unauthenticated and overly open API

- `GET /tests` and `GET /stats` require **no** token (aggregate outcomes leak).
- `POST /tests` is open (anyone can mint tokens).
- CORS is `allow_origins=["*"]`.
- Backend port `8000` is published on the host, so the UI is not the only client.

### 5.6 Secrets handling

Compose embeds `POSTGRES_PASSWORD=bayora` and `BAYORA_SECRET=dev-secret-change-me`. `BAYORA_LEDGER_SECRET` defaults in code if unset. Per-test Fernet keys are **derived from one master**; leaking the master decrypts every test. This is demo-only.

### 5.7 Audit is not independently reconstructable by a third party

HMAC verification requires sharing `BAYORA_LEDGER_SECRET`. A judge without the secret cannot verify signatures (they can still re-hash bodies if they have the stored canonical JSON). There is no public-key signature, Merkle checkpoint, or WORM store. Ledger events are visible to **either** team token during the test and may include finding excerpts.

### 5.8 Side channels

Red and blue share one Python runtime, one DB, and one model. Timing of `execute`, CPU steal, and memory pressure can encode “defended vs not.” cgroup limits are **per service**, not per team or per test. I/O and cache side channels are **unmitigated**.

### 5.9 Container surface

Seccomp and cap-drop apply to **backend only**. Frontend (nginx), Postgres, and Ollama run with image defaults (often root). The seccomp profile still allows `clone` / `fork` / `execve`. Filesystems are not `read_only`. This is not gVisor/Firecracker; a container breakout is outside the PoC claim but also not demonstrated as prevented.

### 5.10 `llm` network egress

The `llm` bridge is not `internal`, so Ollama can reach the internet to pull weights. A compromised Ollama could exfiltrate prompts. We rely on “only backend is attached,” not on an egress allowlist.

## 6. When guarantees fail

| Condition | What breaks |
| --- | --- |
| Operator uses the UI “acting as” toggle with both tokens | Tenant confidentiality is a UI fiction |
| `BAYORA_SECRET` leaked | All sealed payloads decryptable |
| `BAYORA_LEDGER_SECRET` leaked or default left in place | Attacker can forge ledger events that still verify |
| Backend process compromised | Full cross-tenant read; arbitrary Ollama prompts |
| Compose networks flattened to one bridge | Frontend can reach db/Ollama; isolation script fails |
| Ollama down and mock path used | Findings are **not** measurements of the client LLM |
| Two tests overlap on the same Ollama | Possible KV-cache / context contamination |
| Test already `concluded` | Mutual payload read is **intended**; isolation no longer applies |

## 7. Validity of safety findings

A finding from this PoC is a **demo of the control loop** (seal → execute → ledger), not a production-grade safety result, unless:

- the real Ollama model was used (not the mock fallback),
- blue text was not leaked in `reply_excerpt`,
- no other test shared the model session,
- the ledger `chain_valid` is true under a secret the verifier actually controls.

Keyword heuristics (`bomb`, `jailbreak`, …) are **not** a safety classifier.

## 8. Future improvements (priority if more time)

1. Separate red/blue browser sessions; never return both tokens in one response.
2. Redact model output; apply blue policy without putting raw defense text in the red-visible prompt path.
3. Per-test Ollama session or explicit cache flush; never share KV-cache across evaluations.
4. Authenticate `/tests` and `/stats`; stop publishing the API to the host if the UI is enough.
5. Split red-worker / blue-policy / model-gateway processes so compromise of one tenant runtime is not total.
6. Ed25519 (or similar) ledger signatures so judges verify without the HMAC secret.
7. Read-only rootfs, pids limits, rootless engine; tighten seccomp; extend hardening beyond the API container.

## 9. One-sentence claim

**We prevent casual cross-team HTTP reads and direct tenant access to Postgres/Ollama on the default Compose networks, and we detect ledger tampering if the HMAC secret is held. We do not prevent a trusted-backend compromise, shared-UI token leakage, model-output inference of defenses, KV-cache contamination, or timing side channels.**
