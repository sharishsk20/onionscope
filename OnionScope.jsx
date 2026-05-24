import { useState, useEffect, useRef } from "react";

// ─── Colour palette ───────────────────────────────────────────────
const C = {
  bg:       "#060a10",
  surface:  "#0d1520",
  border:   "#1a2d45",
  accent:   "#00c9ff",
  accent2:  "#ff6b35",
  green:    "#00ff88",
  yellow:   "#ffd700",
  red:      "#ff4455",
  muted:    "#4a6080",
  text:     "#c8ddf0",
  textDim:  "#607080",
};

// ─── Synthetic data (mirrors backend output) ──────────────────────
const DEMO_RELAY_STATS = {
  total_relays: 7483,
  guard_nodes:  2841,
  exit_nodes:    987,
  top_countries: [
    { country: "de", count: 1243 },
    { country: "us", count: 1102 },
    { country: "fr", count:  698 },
    { country: "nl", count:  612 },
    { country: "ru", count:  445 },
    { country: "ch", count:  389 },
    { country: "gb", count:  312 },
    { country: "se", count:  287 },
    { country: "ca", count:  201 },
    { country: "at", count:  194 },
  ],
};

const DEMO_MATCHES = [
  {
    entry_src: "192.168.1.12", entry_dst: "185.102.52.3",
    exit_src:  "77.22.32.7",  exit_dst:  "10.0.0.3",
    confidence: 99.8, verdict: "HIGH - Strong correlation detected",
    lag_seconds: 0,
    scores: { burst_correlation: 99.7, volume_similarity: 99.7, iat_similarity: 99.7, packet_count: 100, duration: 100 },
  },
  {
    entry_src: "192.168.1.11", entry_dst: "185.101.51.2",
    exit_src:  "77.21.31.6",  exit_dst:  "10.0.0.2",
    confidence: 99.2, verdict: "HIGH - Strong correlation detected",
    lag_seconds: 0,
    scores: { burst_correlation: 99.3, volume_similarity: 99.4, iat_similarity: 98.2, packet_count: 100, duration: 100 },
  },
  {
    entry_src: "192.168.1.10", entry_dst: "185.100.50.1",
    exit_src:  "77.20.30.5",  exit_dst:  "10.0.0.1",
    confidence: 98.9, verdict: "HIGH - Strong correlation detected",
    lag_seconds: 0,
    scores: { burst_correlation: 98.5, volume_similarity: 98.5, iat_similarity: 99.2, packet_count: 100, duration: 100 },
  },
  {
    entry_src: "192.168.1.10", entry_dst: "185.100.50.1",
    exit_src:  "77.22.32.7",  exit_dst:  "10.0.0.3",
    confidence: 82.0, verdict: "HIGH - Strong correlation detected",
    lag_seconds: -4,
    scores: { burst_correlation: 78.9, volume_similarity: 62.0, iat_similarity: 95.9, packet_count: 97.1, duration: 99.6 },
  },
  {
    entry_src: "192.168.1.13", entry_dst: "194.165.16.9",
    exit_src:  "45.33.82.11", exit_dst:  "10.0.0.4",
    confidence: 39.5, verdict: "LOW - Weak signal, inconclusive",
    lag_seconds: 12,
    scores: { burst_correlation: 41.0, volume_similarity: 35.2, iat_similarity: 42.1, packet_count: 38.0, duration: 41.2 },
  },
];

const DEMO_NODES = [
  { id: "suspect",  label: "Suspect IP\n192.168.1.12",  x: 80,  y: 200, type: "suspect",  country: "IN" },
  { id: "guard",    label: "Guard Node\n185.102.52.3",  x: 260, y: 200, type: "guard",    country: "DE" },
  { id: "middle",   label: "Middle Node\n45.76.33.102", x: 440, y: 200, type: "middle",   country: "NL" },
  { id: "exit",     label: "Exit Node\n77.22.32.7",    x: 620, y: 200, type: "exit",     country: "FR" },
  { id: "dest",     label: "Destination\n10.0.0.3",    x: 800, y: 200, type: "dest",     country: "US" },
];

// ─── Helpers ──────────────────────────────────────────────────────
function confColor(v) {
  if (v >= 80) return C.green;
  if (v >= 55) return C.yellow;
  if (v >= 30) return C.accent2;
  return C.red;
}

function ConfBar({ label, value }) {
  return (
    <div style={{ marginBottom: 6 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: C.textDim, marginBottom: 2 }}>
        <span>{label}</span>
        <span style={{ color: confColor(value) }}>{value}%</span>
      </div>
      <div style={{ height: 4, background: C.border, borderRadius: 2 }}>
        <div style={{
          height: "100%", width: `${value}%`,
          background: `linear-gradient(90deg, ${confColor(value)}, ${confColor(value)}88)`,
          borderRadius: 2, transition: "width 1s ease"
        }} />
      </div>
    </div>
  );
}

function StatCard({ label, value, sub, color }) {
  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 8, padding: "16px 20px", flex: 1, minWidth: 140,
    }}>
      <div style={{ fontSize: 11, color: C.textDim, textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || C.accent, fontFamily: "monospace", margin: "4px 0" }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
      {sub && <div style={{ fontSize: 11, color: C.muted }}>{sub}</div>}
    </div>
  );
}

// ─── Circuit Visualizer ───────────────────────────────────────────
function CircuitMap({ match }) {
  const nodeColor = { suspect: C.accent2, guard: C.green, middle: C.accent, exit: C.yellow, dest: C.red };
  const W = 880, H = 140;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: "auto" }}>
      <defs>
        <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill={C.muted} />
        </marker>
        {DEMO_NODES.map(n => (
          <filter key={n.id} id={`glow-${n.id}`}>
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        ))}
      </defs>

      {/* Edges */}
      {DEMO_NODES.slice(0, -1).map((n, i) => {
        const next = DEMO_NODES[i + 1];
        return (
          <line key={i} x1={n.x + 30} y1={n.y} x2={next.x - 30} y2={next.y}
            stroke={C.muted} strokeWidth={1.5} strokeDasharray="6 3"
            markerEnd="url(#arr)" opacity={0.6} />
        );
      })}

      {/* Nodes */}
      {DEMO_NODES.map(n => (
        <g key={n.id}>
          <circle cx={n.x} cy={n.y} r={28} fill={`${nodeColor[n.type]}22`}
            stroke={nodeColor[n.type]} strokeWidth={1.5}
            filter={`url(#glow-${n.id})`} />
          <text x={n.x} y={n.y - 5} textAnchor="middle" fontSize={9}
            fill={nodeColor[n.type]} fontFamily="monospace" fontWeight={700}>
            {n.label.split("\n")[0]}
          </text>
          <text x={n.x} y={n.y + 7} textAnchor="middle" fontSize={8}
            fill={C.textDim} fontFamily="monospace">
            {n.label.split("\n")[1]}
          </text>
          <text x={n.x} y={n.y + 18} textAnchor="middle" fontSize={8}
            fill={C.muted} fontFamily="monospace">
            [{n.country}]
          </text>
        </g>
      ))}

      {/* Confidence badge */}
      {match && (
        <g>
          <rect x={W / 2 - 60} y={H - 22} width={120} height={18} rx={9}
            fill={`${confColor(match.confidence)}22`} stroke={confColor(match.confidence)} strokeWidth={1} />
          <text x={W / 2} y={H - 10} textAnchor="middle" fontSize={9}
            fill={confColor(match.confidence)} fontFamily="monospace" fontWeight={700}>
            CONFIDENCE: {match.confidence}%
          </text>
        </g>
      )}
    </svg>
  );
}

// ─── Country Bar Chart ────────────────────────────────────────────
function CountryChart({ data }) {
  const max = data[0]?.count || 1;
  const flags = { de: "🇩🇪", us: "🇺🇸", fr: "🇫🇷", nl: "🇳🇱", ru: "🇷🇺", ch: "🇨🇭", gb: "🇬🇧", se: "🇸🇪", ca: "🇨🇦", at: "🇦🇹" };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {data.map(d => (
        <div key={d.country} style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ width: 20, fontSize: 13 }}>{flags[d.country] || "🌐"}</span>
          <span style={{ width: 24, fontSize: 10, color: C.textDim, textTransform: "uppercase", fontFamily: "monospace" }}>{d.country}</span>
          <div style={{ flex: 1, height: 6, background: C.border, borderRadius: 3 }}>
            <div style={{
              height: "100%", width: `${(d.count / max) * 100}%`,
              background: `linear-gradient(90deg, ${C.accent}, ${C.accent}66)`,
              borderRadius: 3
            }} />
          </div>
          <span style={{ width: 40, fontSize: 10, color: C.text, textAlign: "right", fontFamily: "monospace" }}>{d.count}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Scrolling log ────────────────────────────────────────────────
const LOG_MSGS = [
  "[HARVESTER] Connected to Onionoo relay API",
  "[HARVESTER] Fetched 7,483 active relays",
  "[DB] Stored relay consensus snapshot",
  "[ANALYSER] Loaded synthetic flow dataset — 10 flows",
  "[CORRELATOR] Evaluating 5×5 = 25 flow pairs",
  "[CORRELATOR] Circuit match: 192.168.1.12 ↔ 77.22.32.7 — 99.8%",
  "[CORRELATOR] Circuit match: 192.168.1.11 ↔ 77.21.31.6 — 99.2%",
  "[CORRELATOR] Circuit match: 192.168.1.10 ↔ 77.20.30.5 — 98.9%",
  "[DB] Saved 3 high-confidence circuit hypotheses",
  "[RELAY] Guard node 185.102.52.3 — DE — bandwidth: 42 MB/s",
  "[RELAY] Exit node 77.22.32.7 — FR — flags: Exit, Stable, Fast",
  "[HARVESTER] Next harvest scheduled in 3600s",
];

function LiveLog() {
  const [lines, setLines] = useState([LOG_MSGS[0]]);
  const [idx, setIdx] = useState(1);
  const ref = useRef(null);

  useEffect(() => {
    const t = setInterval(() => {
      setLines(l => [...l.slice(-20), LOG_MSGS[idx % LOG_MSGS.length]]);
      setIdx(i => i + 1);
    }, 1800);
    return () => clearInterval(t);
  }, [idx]);

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);

  return (
    <div ref={ref} style={{
      fontFamily: "monospace", fontSize: 11, color: C.green,
      background: "#020508", border: `1px solid ${C.border}`,
      borderRadius: 6, padding: 12, height: 140, overflowY: "auto",
      lineHeight: 1.7
    }}>
      {lines.map((l, i) => (
        <div key={i} style={{ opacity: i === lines.length - 1 ? 1 : 0.6 }}>
          <span style={{ color: C.muted }}>{">"} </span>{l}
        </div>
      ))}
      <div style={{ display: "inline-block", width: 7, height: 12, background: C.green, animation: "blink 1s infinite" }} />
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────
export default function OnionScope() {
  const [tab, setTab] = useState("dashboard");
  const [selectedMatch, setSelectedMatch] = useState(DEMO_MATCHES[0]);
  const [running, setRunning] = useState(false);
  const [scanDone, setScanDone] = useState(true);

  const tabs = ["dashboard", "correlator", "relays", "report"];

  function runScan() {
    setRunning(true);
    setScanDone(false);
    setTimeout(() => { setRunning(false); setScanDone(true); }, 3000);
  }

  return (
    <div style={{
      background: C.bg, minHeight: "100vh", color: C.text,
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      padding: "0 0 40px 0",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Orbitron:wght@700;900&display=swap');
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: #1a2d45; border-radius: 2px; }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
      `}</style>

      {/* Header */}
      <div style={{
        background: `linear-gradient(180deg, #0a1828 0%, ${C.bg} 100%)`,
        borderBottom: `1px solid ${C.border}`,
        padding: "20px 32px 0",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
          {/* Onion logo */}
          <svg width={44} height={44} viewBox="0 0 44 44">
            {[18, 14, 10, 6].map((r, i) => (
              <circle key={i} cx={22} cy={22} r={r}
                fill="none" stroke={[C.accent, C.green, C.yellow, C.accent2][i]}
                strokeWidth={1.5} opacity={0.8 - i * 0.1} />
            ))}
            <circle cx={22} cy={22} r={3} fill={C.accent} />
          </svg>
          <div>
            <div style={{ fontFamily: "Orbitron", fontSize: 22, fontWeight: 900, color: C.accent, letterSpacing: 2 }}>
              ONIONSCOPE
            </div>
            <div style={{ fontSize: 10, color: C.muted, letterSpacing: 3 }}>
              TOR FORENSIC ANALYSIS SYSTEM — TN POLICE HACKATHON 2025
            </div>
          </div>
          <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, animation: "pulse 2s infinite" }} />
            <span style={{ fontSize: 10, color: C.green }}>SYSTEM ONLINE</span>
          </div>
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: 2 }}>
          {tabs.map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              background: tab === t ? C.surface : "transparent",
              border: `1px solid ${tab === t ? C.accent : "transparent"}`,
              borderBottom: "none",
              color: tab === t ? C.accent : C.muted,
              padding: "8px 20px",
              fontSize: 11, fontFamily: "inherit",
              cursor: "pointer", borderRadius: "6px 6px 0 0",
              letterSpacing: 1, textTransform: "uppercase",
              transition: "all 0.2s"
            }}>
              {t}
            </button>
          ))}
        </div>
      </div>

      <div style={{ padding: "24px 32px" }}>

        {/* DASHBOARD TAB */}
        {tab === "dashboard" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <div style={{ display: "flex", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>
              <StatCard label="Total Relays" value={DEMO_RELAY_STATS.total_relays} sub="Active in consensus" color={C.accent} />
              <StatCard label="Guard Nodes" value={DEMO_RELAY_STATS.guard_nodes} sub="Entry points" color={C.green} />
              <StatCard label="Exit Nodes"  value={DEMO_RELAY_STATS.exit_nodes}  sub="Observed endpoints" color={C.yellow} />
              <StatCard label="Circuits Found" value={3} sub="High confidence ≥80%" color={C.accent2} />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
              <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20 }}>
                <div style={{ fontSize: 11, color: C.textDim, textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
                  Top Relay Countries
                </div>
                <CountryChart data={DEMO_RELAY_STATS.top_countries} />
              </div>
              <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20 }}>
                <div style={{ fontSize: 11, color: C.textDim, textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>
                  Live System Log
                </div>
                <LiveLog />
                <button onClick={runScan} style={{
                  marginTop: 12, width: "100%",
                  background: running ? C.border : `${C.accent}22`,
                  border: `1px solid ${running ? C.muted : C.accent}`,
                  color: running ? C.muted : C.accent,
                  padding: "8px 0", borderRadius: 4, fontSize: 11,
                  fontFamily: "inherit", cursor: running ? "default" : "pointer",
                  letterSpacing: 1,
                }}>
                  {running ? "⟳ ANALYSING..." : "▶  RUN DEMO ANALYSIS"}
                </button>
              </div>
            </div>

            {/* Circuit map preview */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20 }}>
              <div style={{ fontSize: 11, color: C.textDim, textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
                Circuit Path Visualisation — Top Match
              </div>
              <CircuitMap match={DEMO_MATCHES[0]} />
            </div>
          </div>
        )}

        {/* CORRELATOR TAB */}
        {tab === "correlator" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1.6fr", gap: 16 }}>
              {/* Match list */}
              <div>
                <div style={{ fontSize: 11, color: C.textDim, textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>
                  Correlation Results ({DEMO_MATCHES.length} pairs)
                </div>
                {DEMO_MATCHES.map((m, i) => (
                  <div key={i} onClick={() => setSelectedMatch(m)} style={{
                    background: selectedMatch === m ? `${C.accent}15` : C.surface,
                    border: `1px solid ${selectedMatch === m ? C.accent : C.border}`,
                    borderRadius: 6, padding: "12px 14px", marginBottom: 8,
                    cursor: "pointer", transition: "all 0.15s"
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ fontSize: 10, color: C.textDim }}>PAIR {i + 1}</span>
                      <span style={{
                        fontSize: 12, fontWeight: 700, color: confColor(m.confidence),
                        fontFamily: "monospace"
                      }}>
                        {m.confidence}%
                      </span>
                    </div>
                    <div style={{ fontSize: 10, color: C.text, fontFamily: "monospace" }}>
                      <div>↗ {m.entry_src}</div>
                      <div style={{ color: C.muted }}>↘ {m.exit_src}</div>
                    </div>
                    <div style={{
                      marginTop: 6, height: 3, background: C.border, borderRadius: 2
                    }}>
                      <div style={{
                        height: "100%", width: `${m.confidence}%`,
                        background: confColor(m.confidence), borderRadius: 2
                      }} />
                    </div>
                  </div>
                ))}
              </div>

              {/* Detail panel */}
              {selectedMatch && (
                <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 20 }}>
                  <div style={{ fontSize: 11, color: C.textDim, textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
                    Circuit Analysis Detail
                  </div>

                  <CircuitMap match={selectedMatch} />

                  <div style={{ marginTop: 20, padding: "12px 14px", background: `${confColor(selectedMatch.confidence)}10`, borderRadius: 6, border: `1px solid ${confColor(selectedMatch.confidence)}44`, marginBottom: 16 }}>
                    <div style={{ fontSize: 11, color: confColor(selectedMatch.confidence), fontWeight: 700 }}>
                      {selectedMatch.verdict}
                    </div>
                    <div style={{ fontSize: 10, color: C.textDim, marginTop: 4 }}>
                      Lag: {selectedMatch.lag_seconds}s | Confidence: {selectedMatch.confidence}%
                    </div>
                  </div>

                  <div style={{ fontSize: 11, color: C.textDim, marginBottom: 10, textTransform: "uppercase", letterSpacing: 1 }}>
                    Score Breakdown
                  </div>
                  {Object.entries(selectedMatch.scores).map(([k, v]) => (
                    <ConfBar key={k} label={k.replace(/_/g, " ")} value={v} />
                  ))}

                  <div style={{ marginTop: 16, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    {[
                      ["Entry IP", selectedMatch.entry_src],
                      ["Entry Guard", selectedMatch.entry_dst],
                      ["Exit Node", selectedMatch.exit_src],
                      ["Destination", selectedMatch.exit_dst],
                    ].map(([l, v]) => (
                      <div key={l} style={{ background: C.bg, borderRadius: 4, padding: "8px 10px" }}>
                        <div style={{ fontSize: 9, color: C.textDim, textTransform: "uppercase" }}>{l}</div>
                        <div style={{ fontSize: 11, color: C.text, fontFamily: "monospace", marginTop: 2 }}>{v}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* RELAYS TAB */}
        {tab === "relays" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <div style={{ fontSize: 11, color: C.textDim, textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
              Top Guard Nodes — Live Relay Database
            </div>
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                <thead>
                  <tr style={{ background: "#0a1520", borderBottom: `1px solid ${C.border}` }}>
                    {["Fingerprint", "IP Address", "Country", "AS Name", "BW (MB/s)", "Flags"].map(h => (
                      <th key={h} style={{ padding: "10px 14px", textAlign: "left", color: C.textDim, fontWeight: 600, letterSpacing: 1 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[
                    { fp: "A5B2...F3D1", ip: "185.102.52.3", co: "🇩🇪 DE", as: "Hetzner Online", bw: 84, flags: "Guard Exit Stable Fast" },
                    { fp: "C8E1...2A94", ip: "198.96.155.3", co: "🇺🇸 US", as: "Choopa LLC", bw: 72, flags: "Guard Stable Fast" },
                    { fp: "D3F7...9B11", ip: "77.109.139.33",co: "🇨🇭 CH", as: "Datasix GmbH", bw: 68, flags: "Guard Stable Fast HSDir" },
                    { fp: "E4A2...7C08", ip: "193.11.166.194",co: "🇸🇪 SE", as: "The Tor Project", bw: 61, flags: "Authority Guard Stable" },
                    { fp: "F1B8...4D33", ip: "51.158.67.24",  co: "🇫🇷 FR", as: "Online SAS", bw: 55, flags: "Guard Stable Fast" },
                    { fp: "2A7C...E190", ip: "204.13.164.118",co: "🇺🇸 US", as: "Frantech Solutions", bw: 49, flags: "Guard Exit Fast" },
                    { fp: "3C9F...B042", ip: "45.66.33.45",   co: "🇳🇱 NL", as: "Serverius", bw: 47, flags: "Guard Stable Fast" },
                    { fp: "4D8E...A155", ip: "185.220.101.2", co: "🇩🇪 DE", as: "RETN Limited", bw: 43, flags: "Exit Stable Fast" },
                  ].map((row, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid ${C.border}33`, transition: "background 0.1s" }}
                      onMouseEnter={e => e.currentTarget.style.background = `${C.accent}08`}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                      <td style={{ padding: "9px 14px", color: C.accent, fontFamily: "monospace" }}>{row.fp}</td>
                      <td style={{ padding: "9px 14px", color: C.text, fontFamily: "monospace" }}>{row.ip}</td>
                      <td style={{ padding: "9px 14px", color: C.text }}>{row.co}</td>
                      <td style={{ padding: "9px 14px", color: C.textDim }}>{row.as}</td>
                      <td style={{ padding: "9px 14px", color: C.green, fontFamily: "monospace" }}>{row.bw}</td>
                      <td style={{ padding: "9px 14px" }}>
                        {row.flags.split(" ").map(f => (
                          <span key={f} style={{
                            fontSize: 9, padding: "2px 6px", marginRight: 3, borderRadius: 3,
                            background: f === "Guard" ? `${C.green}22` : f === "Exit" ? `${C.yellow}22` : `${C.accent}15`,
                            color: f === "Guard" ? C.green : f === "Exit" ? C.yellow : C.accent,
                            border: `1px solid ${f === "Guard" ? C.green : f === "Exit" ? C.yellow : C.accent}44`,
                          }}>{f}</span>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* REPORT TAB */}
        {tab === "report" && (
          <div style={{ animation: "fadeIn 0.3s ease", maxWidth: 720 }}>
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 28 }}>
              <div style={{ fontFamily: "Orbitron", fontSize: 14, color: C.accent, letterSpacing: 2, marginBottom: 4 }}>
                ONIONSCOPE FORENSIC REPORT
              </div>
              <div style={{ fontSize: 10, color: C.muted, marginBottom: 24 }}>
                Session ID: a3f7b2c1 | Generated: {new Date().toISOString().slice(0, 19).replace("T", " ")} UTC
              </div>

              {[
                {
                  heading: "DISCLAIMER",
                  content: "This report presents probabilistic correlation results. Confidence scores reflect statistical likelihood of traffic correlation, not legal proof. All findings must be validated through lawful investigative channels before use in legal proceedings.",
                  color: C.yellow
                },
                {
                  heading: "METHODOLOGY",
                  content: "Traffic timing correlation using sliding-window cross-correlation of packet inter-arrival time series, burst pattern matching, and volume fingerprinting. Relay data sourced from the TOR Onionoo API (metrics.torproject.org). Analysis references DeepCorr (Nasr et al., CCS 2018).",
                  color: C.accent
                },
                {
                  heading: "FINDINGS",
                  content: "3 high-confidence TOR circuit hypotheses identified. Origin IP 192.168.1.12 correlated with exit node 77.22.32.7 (FR) at 99.8% confidence. Guard node identified as 185.102.52.3 (DE, Hetzner Online, ASN 24940). Lag between entry and exit traffic: 0 seconds.",
                  color: C.green
                },
                {
                  heading: "CHAIN OF CUSTODY",
                  content: "Analysis performed by OnionScope automated system v1.0. All raw PCAP files and database snapshots preserved. Audit log available for court submission. No original data modified during analysis.",
                  color: C.accent2
                },
              ].map(s => (
                <div key={s.heading} style={{ marginBottom: 20 }}>
                  <div style={{ fontSize: 10, color: s.color, fontWeight: 700, letterSpacing: 2, textTransform: "uppercase", marginBottom: 8 }}>
                    ▸ {s.heading}
                  </div>
                  <div style={{ fontSize: 12, color: C.text, lineHeight: 1.8, paddingLeft: 12, borderLeft: `2px solid ${s.color}44` }}>
                    {s.content}
                  </div>
                </div>
              ))}

              <div style={{ marginTop: 24, display: "flex", gap: 10 }}>
                <button style={{
                  background: `${C.green}22`, border: `1px solid ${C.green}`,
                  color: C.green, padding: "9px 20px", borderRadius: 5,
                  fontSize: 11, fontFamily: "inherit", cursor: "pointer", letterSpacing: 1
                }}>
                  ↓ EXPORT PDF REPORT
                </button>
                <button style={{
                  background: `${C.accent}22`, border: `1px solid ${C.accent}`,
                  color: C.accent, padding: "9px 20px", borderRadius: 5,
                  fontSize: 11, fontFamily: "inherit", cursor: "pointer", letterSpacing: 1
                }}>
                  ↓ EXPORT JSON DATA
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
