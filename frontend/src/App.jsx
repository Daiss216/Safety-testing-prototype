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
import { AuroraBackground } from "@/components/ui/aurora-background";
import GlyphPortal from "@/components/ui/glyph-portal";
import { LiquidMetalButton } from "@/components/ui/liquid-metal-button";

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
const PORTAL_FONT = '"Plus Jakarta Sans", Arial, sans-serif';
const FALLBACK_FONT = "Arial, sans-serif";
// Portal field in the aurora's blues (Tailwind blue-300/600/800/900, violet-200),
// dark enough in the middle (blue-600) to keep the white copy readable.
const PORTAL_BLUE = "#1e40af";
const PORTAL_FIELD = [
  "radial-gradient(circle at 18% 8%, rgba(147,197,253,.55), transparent 34%)",
  "radial-gradient(circle at 82% 20%, rgba(221,214,254,.25), transparent 28%)",
  "radial-gradient(circle at 48% 78%, rgba(30,58,138,.5), transparent 44%)",
  "linear-gradient(135deg, #1e40af 0%, #2563eb 48%, #1e3a8a 100%)",
].join(", ");

// GlyphPortal freezes whichever face is ready when it mounts (and stays static
// if one is still pending), so hold it back until Plus Jakarta Sans loads.
function usePortalFont() {
  const [face, setFace] = useState(null);
  useEffect(() => {
    let settled = false;
    const finish = (value) => {
      if (!settled) {
        settled = true;
        setFace(value);
      }
    };
    const timeout = window.setTimeout(() => finish(FALLBACK_FONT), 1600);
    document.fonts.load('800 100px "Plus Jakarta Sans"', "BAYORA").then(
      (faces) => finish(faces.length ? PORTAL_FONT : FALLBACK_FONT),
      () => finish(FALLBACK_FONT),
    );
    return () => {
      settled = true;
      clearTimeout(timeout);
    };
  }, []);
  return face;
}

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
  const portalFont = usePortalFont();

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
    <AuroraBackground className="h-auto min-h-screen items-stretch justify-start text-blue-900">
      {portalFont ? (
        <GlyphPortal
          word="BAYORA"
          className="bayora-portal"
          fontFamily={portalFont}
          fontWeight={800}
          scrollLength={2.4}
          enterLabel="Enter console"
          style={{
            fontFamily: portalFont,
            "--gp-paper": "transparent",
            "--gp-ink": "var(--text)",
            "--gp-field": PORTAL_BLUE,
          }}
          background={
            <div
              style={{
                position: "absolute",
                inset: 0,
                transform: "scale(var(--gp-field-scale,1))",
                background: PORTAL_FIELD,
              }}
            />
          }
        >
          <div className="w-full max-w-5xl mx-auto">
            <h2 className="text-4xl md:text-6xl font-extrabold tracking-tight max-w-[14ch]">
              Red attacks. Blue defends.
            </h2>
            <p className="mt-6 max-w-[42ch] text-lg md:text-xl text-white/85">
              Every payload sealed per team, every move written to a
              tamper-evident ledger. The evaluation console is right below.
            </p>
          </div>
        </GlyphPortal>
      ) : (
        <div className="h-svh" aria-hidden="true" />
      )}
    <div className="relative w-full max-w-5xl mx-auto px-6 py-10 space-y-16">
      <header className="text-center">
        <h1 className="text-5xl font-extrabold tracking-widest mt-1">BAYORA_</h1>
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
          <p className="text-xl box-title">00 — Operator Access</p>
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
        <p className="text-xl box-title">01 — Start an Evaluation</p>
        <div className="flex items-center gap-3 flex-wrap">
          <LiquidMetalButton
            label="+ NEW EVALUATION"
            onClick={create}
            disabled={busy || !operatorToken.trim()}
          />
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
              <LiquidMetalButton
                label={issued.red ? "RED ISSUED" : "ISSUE RED TOKEN"}
                disabled={busy || issued.red}
                onClick={() => issueTeam("red")}
              />
              <LiquidMetalButton
                label={issued.blue ? "BLUE ISSUED" : "ISSUE BLUE TOKEN"}
                disabled={busy || issued.blue}
                onClick={() => issueTeam("blue")}
              />
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
                  <LiquidMetalButton
                    label={copied ? "COPIED" : "COPY TOKEN"}
                    onClick={copyToken}
                  />
                  <LiquidMetalButton
                    label={`ENTER ${revealed.team.toUpperCase()} CONSOLE`}
                    onClick={enterRevealed}
                  />
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
          <p className="text-xl box-title">Join an Existing Evaluation</p>
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
            <LiquidMetalButton label="JOIN CONSOLE" type="submit" />
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
            <LiquidMetalButton label="LEAVE CONSOLE" onClick={leaveConsole} />
          </div>
        </section>
      )}

      <section className="sketch-box">
        <p className="text-xl box-title">02 — Attack Console</p>
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
          <LiquidMetalButton
            label="SEAL"
            disabled={busy || !session || !payload.trim() || concluded}
            onClick={upload}
          />
          <LiquidMetalButton
            label="EXECUTE"
            disabled={busy || !session || team !== "red" || concluded}
            onClick={execute}
          />
          <LiquidMetalButton
            label="READ"
            disabled={busy || !session}
            onClick={read}
          />
          <LiquidMetalButton
            label="CONCLUDE"
            disabled={busy || !session || concluded}
            onClick={conclude}
          />
          <LiquidMetalButton
            label="VERIFY LEDGER"
            disabled={busy || !session}
            onClick={verify}
          />
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
        <p className="text-xl box-title">03 — Findings</p>
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
                        color: "#1e3a8a",
                        font: { family: "Plus Jakarta Sans", size: 12 },
                      },
                    },
                    y: {
                      grid: { color: "#ddd" },
                      ticks: {
                        color: "#1e3a8a",
                        font: { family: "Plus Jakarta Sans", size: 12 },
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
                        color: "#1e3a8a",
                        font: { family: "Plus Jakarta Sans", size: 12 },
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
          <p className="text-xl box-title">04 — Audit Ledger</p>
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
    </AuroraBackground>
  );
}
