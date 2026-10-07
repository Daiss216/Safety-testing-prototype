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

const outcomeColors = {
  jailbreak_success: "#e84a5f",
  defended: "#4d9de0",
  benign_or_unclear: "#3dd6c4",
};

export default function App() {
  const [testId, setTestId] = useState("");
  const [tokens, setTokens] = useState(null);
  const [team, setTeam] = useState("red");
  const [payload, setPayload] = useState("");
  const [output, setOutput] = useState(null);
  const [error, setError] = useState("");
  const [ledger, setLedger] = useState(null);
  const [stats, setStats] = useState(null);
  const [busy, setBusy] = useState(false);

  const token = tokens ? tokens[team] : "";

  async function call(path, opts = {}) {
    const res = await fetch(`${API}${path}`, {
      ...opts,
      headers: {
        "Content-Type": "application/json",
        "X-Token": token,
        ...(opts.headers || {}),
      },
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `${res.status} error`);
    return data;
  }

  async function run(fn) {
    setBusy(true);
    setError("");
    setOutput(null);
    try {
      setOutput(await fn());
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
      refreshStats();
    }
  }

  const createTest = () =>
    run(async () => {
      const name = prompt("Evaluation name?", "demo-evaluation") || "demo";
      const r = await call("/tests", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      setTestId(r.test_id);
      setTokens({ red: r.red_token, blue: r.blue_token });
      return r;
    });

  const upload = () =>
    run(() =>
      call(`/tests/${testId}/payloads`, {
        method: "POST",
        body: JSON.stringify({ content: payload }),
      }).then((r) => ({
        ...r,
        note: `payload #${r.payload_id} sealed (team=${team})`,
      })),
    );

  const execute = () =>
    run(() => call(`/tests/${testId}/execute`, { method: "POST" }));
  const conclude = () =>
    run(() => call(`/tests/${testId}/conclude`, { method: "POST" }));
  const readPayloads = () => run(() => call(`/tests/${testId}/payloads`));

  const viewLedger = () =>
    run(async () => {
      const r = await call(`/tests/${testId}/ledger`);
      setLedger(r);
      return { note: `ledger fetched: ${r.events.length} events` };
    });

  async function refreshStats() {
    try {
      setStats(await call("/stats"));
    } catch {
      /* ignore */
    }
  }
  useEffect(() => {
    refreshStats();
  }, []);

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">
            <span className="text-cyan-400">BAYORA</span>{" "}
            <span className="text-slate-300 text-xl">
              | Secure Adversarial AI Testing — PoC
            </span>
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Red/blue evaluation with sealed payloads, per-test crypto isolation
            and a tamper-evident SHA-256 audit ledger.
          </p>
        </div>
        <button onClick={createTest} disabled={busy} className="btn btn-cyan">
          + New Evaluation
        </button>
      </div>

      {tokens && (
        <div className="card border-yellow-700 bg-yellow-950/30 text-sm">
          <b className="text-yellow-400">Test {testId}</b> — hand each token
          ONLY to its team:
          <span className="block mt-1 text-red-400">RED: {tokens.red}</span>
          <span className="block text-blue-400">BLUE: {tokens.blue}</span>
        </div>
      )}

      <div className="grid md:grid-cols-2 gap-6">
        <div className="card space-y-3">
          <div className="flex gap-2 items-center">
            <span className="label">acting as</span>
            {["red", "blue"].map((t) => (
              <button
                key={t}
                onClick={() => setTeam(t)}
                className={`btn ${t === "red" ? "btn-red" : "btn-blue"} ${team === t ? "ring-2 ring-white" : "opacity-60"}`}
              >
                {t.toUpperCase()} TEAM
              </button>
            ))}
          </div>
          <textarea
            className="input h-28"
            placeholder={
              team === "red"
                ? "Adversarial prompt / jailbreak sequence…"
                : "Defensive note / guardrail description…"
            }
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
          />
          <div className="flex flex-wrap gap-2">
            <button
              disabled={busy || !testId || !payload}
              onClick={upload}
              className="btn btn-ghost"
            >
              Seal & Upload
            </button>
            <button
              disabled={busy || !testId || team !== "red"}
              onClick={execute}
              className="btn btn-red"
            >
              Execute Attack vs LLM
            </button>
            <button
              disabled={busy || !testId}
              onClick={readPayloads}
              className="btn btn-ghost"
            >
              Read Payloads (isolation test)
            </button>
            <button
              disabled={busy || !testId}
              onClick={conclude}
              className="btn btn-blue"
            >
              Conclude Test
            </button>
            <button
              disabled={busy || !testId}
              onClick={viewLedger}
              className="btn btn-cyan"
            >
              Verify Audit Ledger
            </button>
          </div>
          {error && <p className="text-red-400 text-sm">⛔ {error}</p>}
          {output && (
            <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs overflow-auto max-h-56">
              {JSON.stringify(output, null, 2)}
            </pre>
          )}
        </div>

        <div className="card space-y-4">
          <h2 className="label">Findings Overview</h2>
          {stats ? (
            <>
              <Bar
                data={{
                  labels: Object.keys(stats.per_day),
                  datasets: [
                    {
                      label: "Findings / day",
                      data: Object.values(stats.per_day),
                      backgroundColor: "#3dd6c4",
                    },
                  ],
                }}
                options={{ plugins: { legend: { display: false } } }}
              />
              <Doughnut
                data={{
                  labels: Object.keys(stats.outcomes),
                  datasets: [
                    {
                      data: Object.values(stats.outcomes),
                      backgroundColor: Object.keys(stats.outcomes).map(
                        (k) => outcomeColors[k],
                      ),
                    },
                  ],
                }}
              />
            </>
          ) : (
            <p className="text-slate-500 text-sm">
              No findings yet — run an attack.
            </p>
          )}
        </div>
      </div>

      {ledger && (
        <div className="card">
          <h2 className="label mb-2">
            Audit Ledger —{" "}
            {ledger.chain_valid ? (
              <span className="text-emerald-400">
                ✔ chain intact (SHA-256 + HMAC verified)
              </span>
            ) : (
              <span className="text-red-400">⛔ TAMPERING DETECTED</span>
            )}
          </h2>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-slate-500">
                <th>#</th>
                <th>event</th>
                <th>time</th>
                <th>hash</th>
                <th>sig</th>
              </tr>
            </thead>
            <tbody>
              {ledger.events.map((e) => (
                <tr
                  key={e.seq}
                  className={e.tampered ? "text-red-400" : "text-slate-300"}
                >
                  <td>{e.seq}</td>
                  <td>{e.type}</td>
                  <td>{new Date(e.ts * 1000).toLocaleString()}</td>
                  <td className="font-mono">{e.hash}</td>
                  <td className="font-mono">{e.signature}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
