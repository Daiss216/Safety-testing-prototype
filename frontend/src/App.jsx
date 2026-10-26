import { useEffect, useState } from "react";
import { Bar, Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
);

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const MONO = {
  jailbreak_success: "#111111",
  defended: "#777777",
  benign_or_unclear: "#cccccc",
};

async function api(path, { token = "", operatorToken = "", ...options } = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { "X-Token": token } : {}),
      ...(operatorToken ? { "X-Operator-Token": operatorToken } : {}),
      ...(options.headers || {}),
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message =
      typeof data.detail === "string"
        ? data.detail
        : JSON.stringify(data.detail || {});
    throw new Error(message || `HTTP ${response.status}`);
  }
  return data;
}

export default function App() {
  const [operatorToken, setOperatorToken] = useState("");
  const [handoff, setHandoff] = useState(null);
  const [revealed, setRevealed] = useState(null);
  const [issued, setIssued] = useState({});
  const [session, setSession] = useState(null);
  const [joinId, setJoinId] = useState("");
  const [joinTeam, setJoinTeam] = useState("red");
  const [joinToken, setJoinToken] = useState("");
  const [payload, setPayload] = useState("");
  const [out, setOut] = useState(null);
  const [err, setErr] = useState("");
  const [ledger, setLedger] = useState(null);
  const [stats, setStats] = useState(null);
  const [busy, setBusy] = useState(false);
  const [concluded, setConcluded] = useState(false);
  const [copied, setCopied] = useState(false);

  const testId = session?.testId || "";
  const team = session?.team || "";
  const token = session?.token || "";

  async function refreshStats(
    activeSession = session,
    currentOperator = operatorToken,
  ) {
    try {
      const result = activeSession
        ? await api("/stats", { token: activeSession.token })
        : currentOperator
          ? await api("/stats", { operatorToken: currentOperator })
          : null;
      setStats(result);
    } catch {
      setStats(null);
    }
  }

  // The other team may have concluded; ask the server instead of trusting local state.
  async function refreshStatus(activeSession = session) {
    if (!activeSession) return;
    try {
      const result = await api(`/tests/${activeSession.testId}/ledger`, {
        token: activeSession.token,
      });
      setConcluded(result.status === "concluded");
    } catch {
      // Bad token or unknown test: the next action will surface the error.
    }
  }

  useEffect(() => {
    refreshStats();
    refreshStatus();
    // Refresh when credentials / active session change.
  }, [session, operatorToken]);

  async function run(action) {
    setBusy(true);
    setErr("");
    setOut(null);
    try {
      const result = await action();
      if (result !== undefined) setOut(result);
    } catch (error) {
      setErr(error.message || "Request failed");
    } finally {
      setBusy(false);
      refreshStats();
      refreshStatus();
    }
  }

  function create() {
    const entered = window.prompt("Evaluation name?", "demo-evaluation");
    if (entered === null) return;
    const name = entered.trim();
    if (!name) {
      setErr("Please enter an evaluation name.");
      return;
    }
    run(async () => {
      if (!operatorToken.trim())
        throw new Error("Enter the operator token first.");
      const result = await api("/tests", {
        operatorToken: operatorToken.trim(),
        method: "POST",
        body: JSON.stringify({ name }),
      });
      setSession(null);
      setHandoff({ testId: result.test_id, name });
      setRevealed(null);
      setIssued({});
      setPayload("");
      setLedger(null);
      setConcluded(false);
      return {
        test_id: result.test_id,
        name,
        status: "created — issue team tokens separately",
      };
    });
  }

  function issueTeam(chosen) {
    if (!handoff) return;
    run(async () => {
      const result = await api(`/tests/${handoff.testId}/tokens`, {
        operatorToken: operatorToken.trim(),
        method: "POST",
        body: JSON.stringify({ team: chosen }),
      });
      setRevealed({ team: chosen, token: result.token });
      setIssued((old) => ({ ...old, [chosen]: true }));
      setCopied(false);
      return {
        team: chosen,
        status: "Token issued. Copy it now; it cannot be retrieved again.",
      };
    });
  }

  function enterRevealed() {
    if (!handoff || !revealed) return;
    setSession({
      testId: handoff.testId,
      team: revealed.team,
      token: revealed.token,
    });
    setRevealed(null);
    setPayload("");
    setLedger(null);
    setErr("");
    setOut(null);
    setConcluded(false);
  }

  function joinTest(event) {
    event.preventDefault();
    if (!joinId.trim() || !joinToken.trim()) {
      setErr("Enter your test ID and team token.");
      return;
    }
    setSession({
      testId: joinId.trim(),
      team: joinTeam,
      token: joinToken.trim(),
    });
    setJoinToken("");
    setRevealed(null);
    setPayload("");
    setLedger(null);
    setConcluded(false);
    setErr("");
    setOut({
      test_id: joinId.trim(),
      team: joinTeam,
      status: "joined — credentials checked on next request",
    });
  }

  function leaveConsole() {
    setSession(null);
    setPayload("");
    setLedger(null);
    setErr("");
    setOut(null);
    setConcluded(false);
  }

  const upload = () =>
    run(async () => {
      const result = await api(`/tests/${testId}/payloads`, {
        token,
        method: "POST",
        body: JSON.stringify({ content: payload }),
      });
      return { payload_id: result.payload_id, sealed: result.sealed, team };
    });

  const execute = () =>
    run(() => api(`/tests/${testId}/execute`, { token, method: "POST" }));
  const read = () => run(() => api(`/tests/${testId}/payloads`, { token }));
  const conclude = () =>
    run(async () => {
      const result = await api(`/tests/${testId}/conclude`, {
        token,
        method: "POST",
      });
      setConcluded(true);
      return result;
    });
  const verify = () =>
    run(async () => {
      const result = await api(`/tests/${testId}/ledger`, { token });
      setLedger(result);
      return { chain_valid: result.chain_valid, events: result.events.length };
    });

  async function copyToken() {
    if (!revealed) return;
    try {
      await navigator.clipboard.writeText(revealed.token);
      setCopied(true);
    } catch {
      setErr("Clipboard unavailable. Select and copy the token manually.");
    }
  }

  return (
    <div className="max-w-3xl mx-auto p-6 space-y-8">
      <header className="text-center">
        <h1 className="text-5xl tracking-widest mt-1">BAYORA_</h1>
        <p className="mt-1 text-lg">
          secure red/blue evaluation · PoC build{" "}
          <span className="cursor">▮</span>
        </p>
        <div className="dots mt-4" />
      </header>

      <p className="text-center text-lg px-4">
        red attacks. blue defends. isolated testing, with every move written to
        a tamper-evident ledger.
      </p>

      {!session && (
        <section className="sketch-box space-y-2">
          <p className="text-xl mb-2">00 — Operator Access</p>
          <label htmlFor="operator-token" className="block">
            Operator token
          </label>
          <input
            id="operator-token"
            className="sketch-input w-full"
            type="password"
            autoComplete="off"
            placeholder="BAYORA_OPERATOR_TOKEN"
            value={operatorToken}
            onChange={(e) => setOperatorToken(e.target.value)}
          />
          <p className="text-sm">
            Local demo only: operator credentials must be kept server-side in
            production.
          </p>
        </section>
      )}

      <section className="sketch-box">
        <p className="text-xl mb-2">01 — Start an Evaluation</p>
        <div className="flex items-center gap-3 flex-wrap">
          <button
            className="sketch-btn"
            onClick={create}
            disabled={busy || !operatorToken.trim()}
          >
            + NEW EVALUATION
          </button>
          {(handoff || session) && (
            <span className="sketch-box-sm">
              test: <b>{handoff?.testId || testId}</b>
            </span>
          )}
        </div>
        {!session && handoff && (
          <div className="mt-4 space-y-3">
            <p>
              Evaluation: <b>{handoff.name}</b>
            </p>
            <p className="text-lg">
              Issue each token separately and give it only to its team.
            </p>
            <div className="flex gap-2 flex-wrap">
              <button
                className="sketch-btn"
                disabled={busy || issued.red}
                onClick={() => issueTeam("red")}
              >
                {issued.red ? "RED ISSUED" : "ISSUE RED TOKEN"}
              </button>
              <button
                className="sketch-btn"
                disabled={busy || issued.blue}
                onClick={() => issueTeam("blue")}
              >
                {issued.blue ? "BLUE ISSUED" : "ISSUE BLUE TOKEN"}
              </button>
            </div>
            {revealed && (
              <div className="sketch-box-sm space-y-2">
                <p>
                  {revealed.team.toUpperCase()} TOKEN — GIVE ONLY TO{" "}
                  {revealed.team.toUpperCase()} TEAM
                </p>
                <code className="block break-all select-all">
                  {revealed.token}
                </code>
                <div className="flex gap-2 flex-wrap">
                  <button className="sketch-btn" onClick={copyToken}>
                    {copied ? "COPIED" : "COPY TOKEN"}
                  </button>
                  <button className="sketch-btn" onClick={enterRevealed}>
                    ENTER {revealed.team.toUpperCase()} CONSOLE
                  </button>
                </div>
                <p className="text-sm">
                  Copy before issuing another token; the previous token will no
                  longer be shown.
                </p>
              </div>
            )}
          </div>
        )}
      </section>

      {!session && (
        <section className="sketch-box">
          <p className="text-xl mb-2">Join an Existing Evaluation</p>
          <form className="space-y-2" onSubmit={joinTest}>
            <input
              className="sketch-input w-full"
              placeholder="Test ID"
              value={joinId}
              onChange={(e) => setJoinId(e.target.value)}
            />
            <select
              className="sketch-input w-full"
              value={joinTeam}
              onChange={(e) => setJoinTeam(e.target.value)}
            >
              <option value="red">Red Team</option>
              <option value="blue">Blue Team</option>
            </select>
            <input
              className="sketch-input w-full"
              type="password"
              autoComplete="off"
              placeholder="Your team's token only"
              value={joinToken}
              onChange={(e) => setJoinToken(e.target.value)}
            />
            <button className="sketch-btn" type="submit">
              JOIN CONSOLE
            </button>
          </form>
        </section>
      )}

      {session && (
        <section className="sketch-box">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div>
              <p className="text-xl">{team.toUpperCase()} TEAM CONSOLE</p>
              <p>
                test: <b>{testId}</b>
              </p>
            </div>
            <button className="sketch-btn" onClick={leaveConsole}>
              LEAVE CONSOLE
            </button>
          </div>
        </section>
      )}

      <section className="sketch-box">
        <p className="text-xl mb-2">02 — Attack Console</p>
        <p className="mb-3 text-lg">
          {session
            ? `${team.toUpperCase()} TEAM · ${concluded ? "CONCLUDED" : "ACTIVE"}`
            : "Join a team to begin"}
        </p>
        <textarea
          className="sketch-input h-24"
          placeholder={
            !session
              ? "> join an evaluation first…"
              : team === "red"
                ? "> type an adversarial prompt…"
                : "> describe a defense…"
          }
          value={payload}
          onChange={(e) => setPayload(e.target.value)}
          disabled={!session || busy || concluded}
        />
        <div className="flex flex-wrap gap-2 mt-3">
          <button
            className="sketch-btn"
            disabled={busy || !session || !payload.trim() || concluded}
            onClick={upload}
          >
            SEAL
          </button>
          <button
            className="sketch-btn"
            disabled={busy || !session || team !== "red" || concluded}
            onClick={execute}
          >
            EXECUTE
          </button>
          <button
            className="sketch-btn"
            disabled={busy || !session}
            onClick={read}
          >
            READ
          </button>
          <button
            className="sketch-btn"
            disabled={busy || !session || concluded}
            onClick={conclude}
          >
            CONCLUDE
          </button>
          <button
            className="sketch-btn"
            disabled={busy || !session}
            onClick={verify}
          >
            VERIFY LEDGER
          </button>
        </div>
        {err && (
          <p role="alert" className="mt-3 text-lg">
            ✗ REQUEST FAILED — {err}
          </p>
        )}
        {out && (
          <pre className="sketch-pre mt-3">{JSON.stringify(out, null, 2)}</pre>
        )}
      </section>

      <section className="sketch-box">
        <p className="text-xl mb-2">03 — Findings</p>
        {stats && Object.keys(stats.per_day || {}).length > 0 ? (
          <div className="grid sm:grid-cols-2 gap-6">
            <div>
              <Bar
                data={{
                  labels: Object.keys(stats.per_day),
                  datasets: [
                    {
                      data: Object.values(stats.per_day),
                      backgroundColor: "#111",
                      borderColor: "#111",
                      borderWidth: 2,
                    },
                  ],
                }}
                options={{
                  plugins: { legend: { display: false } },
                  scales: {
                    x: {
                      grid: { display: false },
                      ticks: {
                        color: "#111",
                        font: { family: "VT323", size: 15 },
                      },
                    },
                    y: {
                      grid: { color: "#ddd" },
                      ticks: {
                        color: "#111",
                        font: { family: "VT323", size: 15 },
                      },
                    },
                  },
                }}
              />
            </div>
            <div>
              <Doughnut
                data={{
                  labels: Object.keys(stats.outcomes || {}),
                  datasets: [
                    {
                      data: Object.values(stats.outcomes || {}),
                      backgroundColor: Object.keys(stats.outcomes || {}).map(
                        (k) => MONO[k] || "#aaa",
                      ),
                      borderColor: "#111",
                      borderWidth: 2,
                    },
                  ],
                }}
                options={{
                  plugins: {
                    legend: {
                      position: "bottom",
                      labels: {
                        color: "#111",
                        font: { family: "VT323", size: 15 },
                      },
                    },
                  },
                }}
              />
            </div>
          </div>
        ) : (
          <p className="text-lg">no findings yet — run an attack ↑</p>
        )}
      </section>

      {ledger && (
        <section className="sketch-box">
          <p className="text-xl mb-2">04 — Audit Ledger</p>
          <p className="text-lg mb-2">
            {ledger.chain_valid
              ? "✔ chain intact — audit verified"
              : "✗ TAMPERING DETECTED"}
          </p>
          <div className="overflow-x-auto">
            <table className="sketch-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>event</th>
                  <th>time</th>
                  <th>hash</th>
                </tr>
              </thead>
              <tbody>
                {ledger.events.map((e) => (
                  <tr key={e.seq} className={e.tampered ? "line-through" : ""}>
                    <td>{e.seq}</td>
                    <td>{e.type}</td>
                    <td>{new Date(e.ts * 1000).toLocaleTimeString()}</td>
                    <td className="break-all">{e.hash}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <footer className="text-center space-y-1 pb-4">
        <div className="dots mb-3" />
        <p className="text-xl">
          isolation: separate workers · team keys · tamper-evident ledger
        </p>
        <p className="text-[15px]">
          bayora_poc | a secure adversarial AI testing broker |{" "}
          {new Date().getFullYear()}
        </p>
      </footer>
    </div>
  );
}
