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

async function api(path, { token = "", ...opts } = {}) {
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "X-Token": token } : {}),
      ...(opts.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `${res.status} error`);
  return data;
}

function CopyField({ label, value, tone }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className={`label ${tone}`}>{label}</span>
        <button
          type="button"
          className="btn btn-ghost text-xs py-1"
          onClick={async () => {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          }}
        >
          {copied ? "copied" : "copy"}
        </button>
      </div>
      <code className="block bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs break-all">
        {value}
      </code>
    </div>
  );
}

export default function App() {
  const [session, setSession] = useState(null);
  const [handoff, setHandoff] = useState(null);
  const [joinId, setJoinId] = useState("");
  const [joinTeam, setJoinTeam] = useState("red");
  const [joinToken, setJoinToken] = useState("");
  const [payload, setPayload] = useState("");
  const [output, setOutput] = useState(null);
  const [error, setError] = useState("");
  const [ledger, setLedger] = useState(null);
  const [stats, setStats] = useState(null);
  const [busy, setBusy] = useState(false);

  const token = session?.token || "";
  const team = session?.team || null;
  const testId = session?.testId || "";

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
      const r = await api("/tests", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      leaveConsole();
      setHandoff({
        testId: r.test_id,
        red: r.red_token,
        blue: r.blue_token,
      });
      return {
        test_id: r.test_id,
        note: "Tokens are shown once on the handoff card. This browser will keep only the team you enter as.",
      };
    });

  function enterTeam(chosen, creds) {
    setSession({
      testId: creds.testId,
      team: chosen,
      token: creds[chosen],
    });
    setHandoff(null);
    setPayload("");
    setLedger(null);
    setOutput({
      test_id: creds.testId,
      team: chosen,
      note: `This session holds the ${chosen} token only.`,
    });
  }

  function joinTest(e) {
    e.preventDefault();
    const id = joinId.trim();
    const tok = joinToken.trim();
    if (!id || !tok) {
      setError("Need a test id and that team's token.");
      return;
    }
    setHandoff(null);
    setSession({ testId: id, team: joinTeam, token: tok });
    setPayload("");
    setLedger(null);
    setError("");
    setOutput({
      test_id: id,
      team: joinTeam,
      note: `Joined as ${joinTeam}. The other team's token is not in this session.`,
    });
  }

  function leaveConsole() {
    setSession(null);
    setPayload("");
    setLedger(null);
  }

  const upload = () =>
    run(() =>
      api(`/tests/${testId}/payloads`, {
        token,
        method: "POST",
        body: JSON.stringify({ content: payload }),
      }).then((r) => ({
        ...r,
        note: `payload #${r.payload_id} sealed (team=${team})`,
      })),
    );

  const execute = () =>
    run(() => api(`/tests/${testId}/execute`, { token, method: "POST" }));
  const conclude = () =>
    run(() => api(`/tests/${testId}/conclude`, { token, method: "POST" }));
  const readPayloads = () =>
    run(() => api(`/tests/${testId}/payloads`, { token }));

  const viewLedger = () =>
    run(async () => {
      const r = await api(`/tests/${testId}/ledger`, { token });
      setLedger(r);
      return { note: `ledger fetched: ${r.events.length} events` };
    });

  async function refreshStats() {
    try {
      setStats(await api("/stats"));
    } catch {
      /* ignore */
    }
  }
  useEffect(() => {
    refreshStats();
  }, []);

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">
            <span className="text-cyan-400">BAYORA</span>{" "}
            <span className="text-slate-300 text-xl">
              | Secure Adversarial AI Testing — PoC
            </span>
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            One browser session, one team token. Model replies are isolated from
            tenants; the ledger stores hashes, not excerpts.
          </p>
        </div>
        <div className="flex gap-2">
          {session && (
            <button onClick={leaveConsole} className="btn btn-ghost">
              Leave console
            </button>
          )}
          <button onClick={createTest} disabled={busy} className="btn btn-cyan">
            + New Evaluation
          </button>
        </div>
      </div>

      {handoff && (
        <div className="card border-yellow-700 bg-yellow-950/30 space-y-3">
          <p className="text-sm">
            <b className="text-yellow-400">Handoff — test {handoff.testId}</b>
            <span className="text-slate-300">
              {" "}
              Copy each token to its team (second browser or teammate), then
              enter <em>one</em> console. The other token is dropped from this
              page.
            </span>
          </p>
          <div className="grid md:grid-cols-2 gap-3">
            <CopyField
              label="Red token — give only to red"
              value={handoff.red}
              tone="text-red-400"
            />
            <CopyField
              label="Blue token — give only to blue"
              value={handoff.blue}
              tone="text-blue-400"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              className="btn btn-red"
              onClick={() => enterTeam("red", handoff)}
            >
              Enter RED console
            </button>
            <button
              className="btn btn-blue"
              onClick={() => enterTeam("blue", handoff)}
            >
              Enter BLUE console
            </button>
          </div>
        </div>
      )}

      {!session && (
        <form className="card space-y-3" onSubmit={joinTest}>
          <h2 className="label">Join an existing evaluation (one token)</h2>
          <div className="grid md:grid-cols-3 gap-2">
            <input
              className="input"
              placeholder="test id"
              value={joinId}
              onChange={(e) => setJoinId(e.target.value)}
            />
            <select
              className="input"
              value={joinTeam}
              onChange={(e) => setJoinTeam(e.target.value)}
            >
              <option value="red">red team</option>
              <option value="blue">blue team</option>
            </select>
            <input
              className="input"
              placeholder="your team token only"
              value={joinToken}
              onChange={(e) => setJoinToken(e.target.value)}
            />
          </div>
          <button className="btn btn-ghost" type="submit">
            Join console
          </button>
        </form>
      )}

      {session && (
        <div
          className={`card text-sm ${
            team === "red"
              ? "border-red-800 bg-red-950/20"
              : "border-blue-800 bg-blue-950/20"
          }`}
        >
          <b className={team === "red" ? "text-red-400" : "text-blue-400"}>
            {team.toUpperCase()} TEAM
          </b>
          <span className="text-slate-300">
            {" "}
            — test {testId}. Other-team payloads stay sealed until conclude.
            Execute returns labels and a reply hash, not model text.
          </span>
        </div>
      )}

      <div className="grid md:grid-cols-2 gap-6">
        <div className="card space-y-3">
          <textarea
            className="input h-28"
            disabled={!session}
            placeholder={
              !session
                ? "Join or create an evaluation first…"
                : team === "red"
                  ? "Adversarial prompt / jailbreak sequence…"
                  : "Defensive note / guardrail description…"
            }
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
          />
          <div className="flex flex-wrap gap-2">
            <button
              disabled={busy || !session || !payload}
              onClick={upload}
              className="btn btn-ghost"
            >
              Seal & Upload
            </button>
            <button
              disabled={busy || !session || team !== "red"}
              onClick={execute}
              className="btn btn-red"
            >
              Execute Attack vs LLM
            </button>
            <button
              disabled={busy || !session}
              onClick={readPayloads}
              className="btn btn-ghost"
            >
              Read Payloads (isolation test)
            </button>
            <button
              disabled={busy || !session}
              onClick={conclude}
              className="btn btn-blue"
            >
              Conclude Test
            </button>
            <button
              disabled={busy || !session}
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
