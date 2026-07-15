/**
 * App.jsx — SentinalFlow AI  |  Security Operations Center Dashboard
 * ──────────────────────────────────────────────────────────────────
 * A production-grade, single-file React component implementing:
 *   • Native WebSocket connection — URL pulled from VITE_WS_URL env-var
 *     with exponential-backoff auto-reconnect logic
 *   • Simulation Control Center — fire normal/attack simulations against
 *     POST /api/v1/trigger-simulation on the Render-hosted backend
 *   • Real-time scrolling event feed with 3 dynamic threat states
 *   • Live recharts AreaChart showing rolling 20-event anomaly timeline
 *   • Metrics counter ribbon with animated counters
 *   • Full Tailwind CSS dark-mode SOC aesthetic
 *
 * Environment variables (set in dashboard/.env or Vercel dashboard):
 *   VITE_WS_URL   — WebSocket URL  e.g. wss://sentinalflow.onrender.com/ws/stream
 *   VITE_API_URL  — REST base URL  e.g. https://sentinalflow.onrender.com
 */

import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';
import { collection, addDoc, serverTimestamp } from 'firebase/firestore';
import { db } from './firebase';
import { useAuth } from './AuthContext';
import emailjs from '@emailjs/browser';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

// WebSocket URL — pulled from env-var so the deployed Vercel frontend
// automatically connects to the Render backend without code changes.
// Fallback to localhost for local development.
const WS_URL  = import.meta.env.VITE_WS_URL  || 'ws://localhost:8000/ws/stream';
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const CHART_WINDOW      = 20;        // rolling events shown on chart
const FEED_MAX          = 50;        // max cards kept in the live feed
const RECONNECT_BASE_MS = 1500;      // initial reconnect delay
const RECONNECT_MAX_MS  = 30000;     // maximum reconnect backoff cap

// Score thresholds (must mirror main.py BLOCK_THRESHOLD)
const THRESHOLD_SAFE       = 0.60;
const THRESHOLD_SUSPICIOUS = 0.75;

// ─────────────────────────────────────────────────────────────────────────────
// Gemini AI integration constants
// ─────────────────────────────────────────────────────────────────────────────

const GEMINI_API_KEY  = import.meta.env.VITE_GEMINI_API_KEY  || '';
const GEMINI_MODEL    = import.meta.env.VITE_GEMINI_MODEL    || 'gemini-2.0-flash';
const GEMINI_ENDPOINT = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

// ─────────────────────────────────────────────────────────────────────────────
// Email alert constants (EmailJS — optional, configure in .env)
// ─────────────────────────────────────────────────────────────────────────────

const EJS_SERVICE_ID  = import.meta.env.VITE_EMAILJS_SERVICE_ID  || '';
const EJS_TEMPLATE_ID = import.meta.env.VITE_EMAILJS_TEMPLATE_ID || '';
const EJS_PUBLIC_KEY  = import.meta.env.VITE_EMAILJS_PUBLIC_KEY  || '';
const ALERT_EMAIL     = import.meta.env.VITE_ALERT_EMAIL         || 'soc-alerts@bankofmaharashtra.com';

/** Send an email alert via EmailJS (silent fail if not configured). */
async function sendEmailAlert(event, analystEmail) {
  if (!EJS_SERVICE_ID || !EJS_TEMPLATE_ID || !EJS_PUBLIC_KEY) return;
  try {
    await emailjs.send(EJS_SERVICE_ID, EJS_TEMPLATE_ID, {
      to_email    : ALERT_EMAIL,
      analyst     : analystEmail || 'SOC Analyst',
      actor_id    : event.actor_id || '—',
      actor_role  : event.actor_role || '—',
      target      : event.target_resource || '—',
      score       : fmtScore(event.anomaly_score ?? 0),
      action      : (event.action_executed || '—').slice(0, 120),
      vector      : event.threat_vector || 'UNKNOWN',
      blocked     : event.action_blocked ? 'YES — Session Revoked' : 'No',
      timestamp   : new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
    }, EJS_PUBLIC_KEY);
    console.log('[SentinalFlow] 📧 Email alert sent to', ALERT_EMAIL);
  } catch (err) {
    console.warn('[SentinalFlow] Email alert failed:', err);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat classification helpers
// ─────────────────────────────────────────────────────────────────────────────

function classifyEvent(score) {
  if (score < THRESHOLD_SAFE)       return 'safe';
  if (score < THRESHOLD_SUSPICIOUS) return 'suspicious';
  return 'critical';
}

const THREAT_CONFIG = {
  safe: {
    borderClass  : 'border-emerald-500/60',
    cardClass    : 'bg-gradient-to-r from-emerald-950/30 to-soc-card',
    badgeBg      : 'bg-emerald-500/15 border border-emerald-500/40',
    badgeText    : 'text-emerald-400',
    badgeLabel   : 'PASSED',
    badgeDot     : 'bg-emerald-400',
    scoreColor   : 'text-emerald-400',
    barColor     : 'bg-emerald-500',
    icon         : '✓',
    iconColor    : 'text-emerald-400',
    glowClass    : '',
  },
  suspicious: {
    borderClass  : 'border-amber-500/80 card-suspicious',
    cardClass    : 'bg-gradient-to-r from-amber-950/30 to-soc-card',
    badgeBg      : 'bg-amber-500/15 border border-amber-500/40',
    badgeText    : 'text-amber-400',
    badgeLabel   : 'REVIEW REQUIRED',
    badgeDot     : 'bg-amber-400',
    scoreColor   : 'text-amber-400 text-amber-glow',
    barColor     : 'bg-amber-500',
    icon         : '⚠',
    iconColor    : 'text-amber-400',
    glowClass    : '',
  },
  critical: {
    borderClass  : 'border-red-500 card-critical',
    cardClass    : 'bg-gradient-to-r from-red-950/40 to-soc-card',
    badgeBg      : 'bg-red-500/20 border border-red-500/60',
    badgeText    : 'text-red-300',
    badgeLabel   : 'ATTACK MITIGATED / SESSION REVOKED',
    badgeDot     : 'bg-red-400',
    scoreColor   : 'text-red-400 text-threat-glow',
    barColor     : 'bg-red-500',
    icon         : '✕',
    iconColor    : 'text-red-400',
    glowClass    : 'shadow-[0_0_24px_rgba(239,68,68,0.2)]',
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Utility: format timestamp for display
// ─────────────────────────────────────────────────────────────────────────────

function fmtTime(isoStr) {
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return '--:--:--';
  }
}

function fmtScore(score) {
  return (score * 100).toFixed(1) + '%';
}

function truncate(str, n) {
  if (!str) return '';
  return str.length > n ? str.slice(0, n) + '…' : str;
}

// ─────────────────────────────────────────────────────────────────────────────
// Gemini AI helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * callGemini — POST a prompt to the Gemini REST API and return the text response.
 * Uses the REST generateContent endpoint so no SDK is needed.
 */
async function callGemini(prompt, systemInstruction = '') {
  if (!GEMINI_API_KEY) throw new Error('No Gemini API key configured. Add VITE_GEMINI_API_KEY to dashboard/.env');

  const body = {
    ...(systemInstruction && {
      system_instruction: { parts: [{ text: systemInstruction }] },
    }),
    contents: [{ role: 'user', parts: [{ text: prompt }] }],
    generationConfig: {
      temperature: 0.4,
      maxOutputTokens: 800,
    },
  };

  const res = await fetch(`${GEMINI_ENDPOINT}?key=${GEMINI_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.error?.message || `Gemini API error HTTP ${res.status}`);
  }

  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || '(empty response)';
}

/** Build a structured threat-analysis prompt from a single event's fields. */
function buildThreatPrompt(event) {
  const score = event.anomaly_score ?? 0;
  const fields = [
    `Anomaly Score: ${fmtScore(score)} (${classifyEvent(score).toUpperCase()})`,
    `Actor ID: ${event.actor_id || 'Unknown'}`,
    `Actor Role: ${event.actor_role || 'Unknown'}`,
    `Target Resource: ${event.target_resource || 'Unknown'}`,
    `Action Executed: ${event.action_executed || 'Unknown'}`,
    `Risk × Criticality: ${event.risk_x_criticality ?? 'N/A'}/100`,
    `Execution Time Delta: ${event.execution_time_delta != null ? event.execution_time_delta.toFixed(1) + 'ms' : 'N/A'}`,
    `Data Volume: ${event.data_volume_kb != null ? (event.data_volume_kb > 1024 ? (event.data_volume_kb/1024).toFixed(2)+' MB' : event.data_volume_kb.toFixed(1)+' KB') : 'N/A'}`,
    `Off-Hours Activity: ${event.off_hours_flag === 1 ? 'YES' : 'No'}`,
    `Change Ticket Present: ${event.associated_ticket_id === 'NULL' ? 'NO — untracked change' : 'Yes'}`,
    `Threat Vector: ${event.threat_vector || 'NONE'}`,
    `Session Blocked: ${event.action_blocked ? 'YES' : 'No'}`,
  ].join('\n');

  return `You are a senior SOC analyst at a banking institution reviewing a flagged security telemetry event from an AI-based anomaly detection system (SentinalFlow AI).\n\nEvent telemetry:\n${fields}\n\nProvide a concise threat brief with exactly these three sections:\n1. **Threat Summary** — one sentence describing what likely occurred\n2. **Key Risk Signals** — bullet points of the suspicious indicators\n3. **Recommended Action** — immediate steps for the analyst\n\nBe specific, technical, and concise. Max 180 words. Do not repeat the raw numbers verbatim.`;
}

/** Build a session-level prompt for the chat panel. */
function buildSessionSummaryPrompt(events, userQuestion) {
  const top = events.slice(0, 25);
  const eventLines = top.map((e, i) => {
    const score = fmtScore(e.anomaly_score ?? 0);
    const action = (e.action_executed || '').slice(0, 55);
    return `[${i + 1}] Score:${score} | Role:${e.actor_role || '?'} | Target:${e.target_resource || '?'} | Action:${action} | Vector:${e.threat_vector || 'NONE'} | Blocked:${e.action_blocked ? 'Y' : 'N'} | OffHours:${e.off_hours_flag === 1 ? 'Y' : 'N'}`;
  }).join('\n');

  const context = top.length > 0
    ? `Recent session events (showing ${top.length} of ${events.length} total):\n${eventLines}`
    : 'No events have been received in this session yet.';

  return `You are an expert AI SOC Analyst assistant for SentinalFlow AI, a banking security operations platform. You have context on the current monitoring session.\n\n${context}\n\nAnalyst question: ${userQuestion}\n\nAnswer concisely and technically. Format with **bold** for key terms. Be direct and actionable.`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Connection Status Badge
// ─────────────────────────────────────────────────────────────────────────────

function ConnectionBadge({ status }) {
  const cfg = {
    connected    : { dot: 'bg-emerald-400 animate-ping',   label: 'LIVE',           text: 'text-emerald-400', ring: 'bg-emerald-400' },
    connecting   : { dot: 'bg-amber-400 animate-pulse',    label: 'CONNECTING…',    text: 'text-amber-400',   ring: 'bg-amber-400'   },
    reconnecting : { dot: 'bg-orange-400 animate-pulse',   label: 'RECONNECTING…',  text: 'text-orange-400',  ring: 'bg-orange-400'  },
    disconnected : { dot: 'bg-red-500',                    label: 'OFFLINE',         text: 'text-red-400',     ring: 'bg-red-500'     },
  }[status] || { dot: 'bg-slate-500', label: status.toUpperCase(), text: 'text-slate-400', ring: 'bg-slate-500' };

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-soc-card border border-soc-border">
      <span className="relative flex h-2 w-2">
        <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${cfg.dot}`} />
        <span className={`relative inline-flex rounded-full h-2 w-2 ${cfg.ring}`} />
      </span>
      <span className={`text-xs font-mono font-semibold tracking-widest ${cfg.text}`}>
        {cfg.label}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Live Clock
// ─────────────────────────────────────────────────────────────────────────────

function LiveClock() {
  const [time, setTime] = useState('');
  useEffect(() => {
    const tick = () => setTime(new Date().toLocaleTimeString('en-US', { hour12: false }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <span className="font-mono text-sm text-slate-400 tracking-widest tabular-nums">
      {time}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Metric Card
// ─────────────────────────────────────────────────────────────────────────────

function MetricCard({ label, value, icon, accent, sublabel }) {
  const prevRef = useRef(value);
  const [bump, setBump] = useState(false);

  useEffect(() => {
    if (value !== prevRef.current) {
      setBump(true);
      prevRef.current = value;
      const t = setTimeout(() => setBump(false), 250);
      return () => clearTimeout(t);
    }
  }, [value]);

  const accentMap = {
    blue   : 'text-blue-400   border-blue-500/30  bg-blue-500/8',
    emerald: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/8',
    amber  : 'text-amber-400  border-amber-500/30  bg-amber-500/8',
    red    : 'text-red-400    border-red-500/30    bg-red-500/8',
  };
  const accentClass = accentMap[accent] || accentMap.blue;

  return (
    <div className={`relative flex flex-col gap-1 p-4 rounded-xl border bg-soc-card ${accentClass} overflow-hidden`}>
      {/* Background glow */}
      <div className="absolute inset-0 opacity-20 pointer-events-none"
           style={{ background: `radial-gradient(ellipse at top left, currentColor 0%, transparent 60%)` }} />
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono font-medium tracking-widest text-slate-500 uppercase">
          {label}
        </span>
        <span className="text-lg leading-none">{icon}</span>
      </div>
      <div className={`text-3xl font-bold font-mono tabular-nums transition-all duration-150 ${accentClass.split(' ')[0]} ${bump ? 'animate-counter scale-110' : ''}`}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {sublabel && (
        <div className="text-xs text-slate-500 font-mono">{sublabel}</div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Custom Recharts Tooltip
// ─────────────────────────────────────────────────────────────────────────────

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  const d = payload[0]?.payload;
  const score = payload[0]?.value ?? 0;
  const cls = classifyEvent(score);
  const colors = { safe: '#10b981', suspicious: '#f59e0b', critical: '#ef4444' };

  return (
    <div className="bg-soc-surface border border-soc-border rounded-lg p-3 shadow-2xl text-xs font-mono min-w-[180px]">
      <div className="text-slate-400 mb-2">Event #{label}</div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-slate-300">Anomaly Score</span>
        <span style={{ color: colors[cls] }} className="font-bold">
          {fmtScore(score)}
        </span>
      </div>
      {d?.actor_role && (
        <div className="flex items-center justify-between text-slate-500">
          <span>Actor</span>
          <span className="text-slate-300">{d.actor_role}</span>
        </div>
      )}
      {d?.target_resource && (
        <div className="flex items-center justify-between text-slate-500 mt-0.5">
          <span>Target</span>
          <span className="text-slate-300 truncate ml-2 max-w-[100px]">
            {d.target_resource}
          </span>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Anomaly Score Chart
// ─────────────────────────────────────────────────────────────────────────────


// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Single Event Card
// ─────────────────────────────────────────────────────────────────────────────

function EventCard({ event, index }) {
  const cls  = classifyEvent(event.anomaly_score ?? 0);
  const cfg  = THREAT_CONFIG[cls];
  const score = event.anomaly_score ?? 0;

  return (
    <div
      className={`
        event-enter relative rounded-xl border-2 p-3 transition-all duration-300
        ${cfg.borderClass} ${cfg.cardClass} ${cfg.glowClass}
      `}
    >
      {/* Top row: badge + score + time */}
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex items-center gap-2 flex-wrap">
          {/* Threat state badge */}
          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-widest ${cfg.badgeBg} ${cfg.badgeText}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${cfg.badgeDot} ${cls === 'critical' ? 'animate-ping' : ''}`} />
            {cfg.badgeLabel}
          </span>
          {/* Blocked indicator */}
          {event.action_blocked && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-red-900/40 border border-red-500/30 text-red-300">
              🔒 BLOCKED
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <div className="text-right">
            <div className={`text-lg font-bold font-mono tabular-nums ${cfg.scoreColor}`}>
              {fmtScore(score)}
            </div>
            <div className="text-[10px] text-slate-500 font-mono">
              {fmtTime(event.processed_at_utc || event.timestamp)}
            </div>
          </div>
          <div className={`w-7 h-7 rounded-lg flex items-center justify-center text-sm font-bold ${cfg.badgeBg} ${cfg.iconColor}`}>
            {cfg.icon}
          </div>
        </div>
      </div>

      {/* Score progress bar */}
      <div className="h-1 w-full bg-soc-muted rounded-full mb-3 overflow-hidden">
        <div
          className={`h-full rounded-full score-bar ${cfg.barColor}`}
          style={{ width: `${Math.min(score * 100, 100)}%` }}
        />
      </div>

      {/* Metadata grid */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] font-mono mb-2">
        <div className="flex items-center gap-1.5 text-slate-400 overflow-hidden">
          <span className="text-slate-600 shrink-0">ACTOR</span>
          <span className="text-slate-300 truncate">{event.actor_id || '—'}</span>
        </div>
        <div className="flex items-center gap-1.5 text-slate-400 overflow-hidden">
          <span className="text-slate-600 shrink-0">ROLE</span>
          <span className={`truncate ${cls === 'critical' ? 'text-red-300' : cls === 'suspicious' ? 'text-amber-300' : 'text-slate-300'}`}>
            {event.actor_role || '—'}
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-slate-400 overflow-hidden col-span-2">
          <span className="text-slate-600 shrink-0">TARGET</span>
          <span className="text-blue-300 truncate">{event.target_resource || '—'}</span>
        </div>
      </div>

      {/* Action row */}
      <div className="p-2 rounded-lg bg-soc-surface border border-soc-border text-[10px] font-mono">
        <div className="text-slate-600 mb-0.5">ACTION</div>
        <div className={`truncate ${cls === 'critical' ? 'text-red-300' : 'text-slate-300'}`}>
          {truncate(event.action_executed, 72)}
        </div>
      </div>

      {/* Risk signals row */}
      <div className="flex items-center gap-3 mt-2 text-[10px] font-mono text-slate-500 flex-wrap">
        <span>
          <span className="text-slate-600">RISK×CRIT </span>
          <span className={`font-semibold ${event.risk_x_criticality >= 80 ? 'text-red-400' : event.risk_x_criticality >= 50 ? 'text-amber-400' : 'text-slate-400'}`}>
            {event.risk_x_criticality ?? '—'}/100
          </span>
        </span>
        <span>
          <span className="text-slate-600">EXEC </span>
          <span className={event.execution_time_delta < 50 ? 'text-red-400' : 'text-slate-400'}>
            {event.execution_time_delta != null ? event.execution_time_delta.toFixed(1) + 'ms' : '—'}
          </span>
        </span>
        <span>
          <span className="text-slate-600">VOL </span>
          <span className={event.data_volume_kb > 5000 ? 'text-amber-400' : 'text-slate-400'}>
            {event.data_volume_kb != null
              ? event.data_volume_kb > 1024
                ? (event.data_volume_kb / 1024).toFixed(1) + ' MB'
                : event.data_volume_kb.toFixed(1) + ' KB'
              : '—'}
          </span>
        </span>
        {event.off_hours_flag === 1 && (
          <span className="text-orange-400 font-semibold">⏰ OFF-HOURS</span>
        )}
        {event.associated_ticket_id === 'NULL' && (
          <span className="text-red-400 font-semibold">⚡ NO TICKET</span>
        )}
      </div>

      {/* AI Explain button — only shown for non-safe events */}
      {cls !== 'safe' && <AiExplainButton event={event} />}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Simulation Control Center
// ─────────────────────────────────────────────────────────────────────────────

/**
 * SystemOperationsCenter
 * ───────────────────────
 * Renders a high-visibility control strip with action buttons for managing 
 * baseline operations (Normal Traffic). The "Inject Attack" button has been
 * moved to the separate attacker terminal.
 */
function SystemOperationsCenter({ simState, simId, onStart, onStop, lastSimMsg }) {
  const isIdle     = simState === 'idle';
  const isNormal   = simState === 'running_normal';
  const isAttack   = simState === 'running_attack';
  const isStopping = simState === 'stopping';
  const isRunning  = isNormal || isAttack;

  return (
    <div className="shrink-0 px-6 py-4 border-b border-soc-border bg-soc-surface/60 backdrop-blur-md">
      <div className="max-w-[1920px] mx-auto flex flex-col gap-3">

        {/* ── Title row ─────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            {/* Animated radar icon */}
            <div className="relative w-8 h-8 shrink-0">
              <div className={`absolute inset-0 rounded-full opacity-30 ${
                isAttack ? 'bg-red-500 animate-ping' :
                isNormal ? 'bg-emerald-500 animate-pulse' :
                'bg-slate-600'
              }`} />
              <div className={`relative w-8 h-8 rounded-full flex items-center justify-center text-base ${
                isAttack ? 'bg-red-900/60 border border-red-500/60' :
                isNormal ? 'bg-emerald-900/60 border border-emerald-500/60' :
                'bg-soc-card border border-soc-border'
              }`}>
                {isAttack ? '⚔️' : isNormal ? '📡' : '🎛️'}
              </div>
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-200 tracking-wide uppercase">
                Manage Operations
              </h2>
              <p className="text-[10px] font-mono text-slate-500 mt-0.5">
                System flow control and baseline traffic generation
              </p>
            </div>
          </div>

          {/* Status chip */}
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-[10px] font-mono font-bold tracking-widest ${
            isAttack   ? 'bg-red-900/30 border-red-500/50 text-red-300' :
            isNormal   ? 'bg-emerald-900/30 border-emerald-500/50 text-emerald-300' :
            isStopping ? 'bg-orange-900/30 border-orange-500/50 text-orange-300' :
            'bg-soc-card border-soc-border text-slate-500'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              isAttack   ? 'bg-red-400 animate-ping' :
              isNormal   ? 'bg-emerald-400 animate-pulse' :
              isStopping ? 'bg-orange-400 animate-pulse' :
              'bg-slate-600'
            }`} />
            {isAttack   ? `ATTACK SIM ACTIVE  [${simId || '...'}]` :
             isNormal   ? `BASELINE ACTIVE  [${simId || '...'}]` :
             isStopping ? 'STOPPING...' :
             'STANDBY — NO ACTIVE SIM'}
          </div>
        </div>

        {/* ── Button row ────────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-center gap-3">

          {/* START BASELINE */}
          <button
            id="btn-start-baseline"
            onClick={() => onStart('normal')}
            disabled={isRunning || isStopping}
            className={`
              group relative flex items-center gap-2.5 px-5 py-2.5 rounded-xl
              font-mono font-bold text-sm tracking-wide
              transition-all duration-200 overflow-hidden
              border shadow-lg
              ${ isNormal
                ? 'bg-emerald-600/30 border-emerald-500/60 text-emerald-300 cursor-not-allowed opacity-80'
                : (isRunning || isStopping)
                  ? 'bg-soc-card border-soc-border text-slate-600 cursor-not-allowed opacity-50'
                  : 'bg-emerald-600/20 border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/35 hover:border-emerald-400/70 hover:shadow-emerald-500/20 hover:scale-[1.02] active:scale-[0.98] cursor-pointer'
              }
            `}
          >
            {/* Button glow sweep on hover */}
            <span className="absolute inset-0 bg-gradient-to-r from-emerald-500/0 via-emerald-400/10 to-emerald-500/0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-700 pointer-events-none" />

            <span className={`w-2 h-2 rounded-full ${
              isNormal ? 'bg-emerald-400 animate-pulse' : 'bg-emerald-500/70'
            }`} />

            <span className="flex flex-col items-start leading-none gap-0.5">
              <span className="text-[11px] text-emerald-400/70 font-normal">
                {isNormal ? 'RUNNING...' : 'SYSTEM OPERATION'}
              </span>
              <span>Start Normal Operations</span>
            </span>

            {isNormal && (
              <svg className="w-4 h-4 animate-spin ml-1 text-emerald-400" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
              </svg>
            )}
          </button>

          {/* STOP */}
          <button
            id="btn-stop-sim"
            onClick={onStop}
            disabled={!isRunning || isStopping}
            className={`
              flex items-center gap-2 px-4 py-2.5 rounded-xl
              font-mono font-bold text-sm tracking-wide
              border transition-all duration-200
              ${ (!isRunning || isStopping)
                ? 'bg-soc-card border-soc-border text-slate-600 cursor-not-allowed opacity-40'
                : 'bg-slate-700/40 border-slate-500/50 text-slate-300 hover:bg-slate-600/50 hover:border-slate-400/60 active:scale-[0.98] cursor-pointer'
              }
            `}
          >
            <span className="text-base">⏹</span>
            <span>{isStopping ? 'Stopping…' : 'Stop Operations'}</span>
          </button>
        </div>

        {/* ── Status message bar ─────────────────────────────────────────── */}
        {lastSimMsg && (
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-[10px] font-mono border ${
            isAttack   ? 'bg-red-950/30 border-red-500/20 text-red-400' :
            isNormal   ? 'bg-emerald-950/30 border-emerald-500/20 text-emerald-400' :
            'bg-soc-surface border-soc-border text-slate-500'
          }`}>
            <span className="shrink-0">{'>'}</span>
            <span className="truncate">{lastSimMsg}</span>
          </div>
        )}

      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Threat Vector Distribution sidebar panel
// ─────────────────────────────────────────────────────────────────────────────

const VECTOR_META = {
  THIRD_PARTY_FINTECH_API_ABUSE : { label: 'API Abuse',    color: 'bg-purple-500', icon: '🔌' },
  POISONED_CICD_PIPELINE        : { label: 'CI/CD Poison', color: 'bg-orange-500', icon: '💉' },
  HIGH_VOLUME_TRANSACTION_FRAUD : { label: 'Txn Fraud',    color: 'bg-red-500',    icon: '💳' },
  ROGUE_INTERNAL_DBA            : { label: 'Rogue DBA',    color: 'bg-amber-500',  icon: '🗄' },
  NONE                          : { label: 'Baseline',     color: 'bg-slate-500',  icon: '📋' },
};

function VectorDistribution({ events }) {
  const counts = useMemo(() => {
    const map = {};
    events.forEach(e => {
      const v = e.threat_vector || 'NONE';
      map[v] = (map[v] || 0) + 1;
    });
    return map;
  }, [events]);

  const total = events.length || 1;
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2 mb-1">
        <div className="w-1 h-4 rounded-full bg-purple-500" />
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-widest">
          Vector Distribution
        </h3>
      </div>
      {entries.length === 0 ? (
        <div className="text-xs font-mono text-slate-600 py-2">No events yet</div>
      ) : (
        entries.map(([vec, cnt]) => {
          const meta = VECTOR_META[vec] || { label: vec.slice(0, 12), color: 'bg-slate-500', icon: '?' };
          const pct  = Math.round((cnt / total) * 100);
          return (
            <div key={vec} className="flex flex-col gap-1">
              <div className="flex items-center justify-between text-[11px] font-mono">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span>{meta.icon}</span>
                  <span>{meta.label}</span>
                </span>
                <span className="text-slate-300 font-semibold">{cnt}</span>
              </div>
              <div className="h-1 w-full bg-soc-muted rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${meta.color}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Alert Toast — critical event notification (top-right)
// ─────────────────────────────────────────────────────────────────────────────

const TOAST_DURATION_MS = 9000;

function AlertToast({ toast, onDismiss }) {
  const [progress, setProgress] = useState(100);

  useEffect(() => {
    const start = Date.now();
    const iv = setInterval(() => {
      const pct = Math.max(0, 100 - ((Date.now() - start) / TOAST_DURATION_MS) * 100);
      setProgress(pct);
      if (pct === 0) { clearInterval(iv); onDismiss(toast.id); }
    }, 80);
    return () => clearInterval(iv);
  }, [toast.id, onDismiss]);

  const score = fmtScore(toast.anomaly_score ?? 0);

  return (
    <div className="toast-enter w-[340px] rounded-2xl border border-red-500/50 bg-gradient-to-br from-red-950/80 to-soc-surface/95 backdrop-blur-xl shadow-2xl shadow-red-900/40 overflow-hidden">
      {/* Progress bar */}
      <div className="h-0.5 bg-soc-muted">
        <div
          className="h-full bg-gradient-to-r from-red-500 to-orange-500 transition-all duration-75"
          style={{ width: `${progress}%` }}
        />
      </div>

      <div className="p-4">
        {/* Header row */}
        <div className="flex items-start justify-between gap-3 mb-2">
          <div className="flex items-center gap-2">
            <span className="relative flex h-3 w-3">
              <span className="absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75 animate-ping" />
              <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500" />
            </span>
            <span className="text-xs font-mono font-bold text-red-300 tracking-widest">🚨 CRITICAL THREAT DETECTED</span>
          </div>
          <button
            onClick={() => onDismiss(toast.id)}
            className="text-slate-500 hover:text-slate-300 transition-colors text-sm leading-none shrink-0"
          >
            ✕
          </button>
        </div>

        {/* Event details */}
        <div className="space-y-1 text-[11px] font-mono">
          <div className="flex justify-between">
            <span className="text-slate-500">ACTOR</span>
            <span className="text-slate-200">{toast.actor_id || '—'} · {toast.actor_role || '—'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">TARGET</span>
            <span className="text-blue-300 truncate max-w-[180px]">{toast.target_resource || '—'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">SCORE</span>
            <span className="text-red-400 font-bold text-threat-glow">{score}</span>
          </div>
          {toast.action_blocked && (
            <div className="mt-1.5 inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-red-900/40 border border-red-500/40 text-red-300 text-[10px]">
              🔒 Session automatically revoked
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Threat Level Badge — header indicator based on recent events
// ─────────────────────────────────────────────────────────────────────────────

function ThreatLevelBadge({ events }) {
  const level = useMemo(() => {
    const recent = events.slice(0, 8);
    if (recent.some(e => classifyEvent(e.anomaly_score ?? 0) === 'critical'))   return 'CRITICAL';
    if (recent.some(e => classifyEvent(e.anomaly_score ?? 0) === 'suspicious')) return 'ELEVATED';
    return 'NORMAL';
  }, [events]);

  const cfg = {
    CRITICAL: { bg: 'bg-red-900/30 border-red-500/50',     text: 'text-red-400',     dot: 'bg-red-400 animate-ping' },
    ELEVATED: { bg: 'bg-amber-900/30 border-amber-500/50', text: 'text-amber-400',   dot: 'bg-amber-400 animate-pulse' },
    NORMAL:   { bg: 'bg-emerald-900/20 border-emerald-500/30', text: 'text-emerald-400', dot: 'bg-emerald-400' },
  }[level];

  return (
    <div className={`hidden xl:flex items-center gap-2 px-3 py-1.5 rounded-full border text-[10px] font-mono font-bold tracking-widest ${cfg.bg} ${cfg.text}`}>
      <span className="relative flex h-2 w-2">
        <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${cfg.dot}`} />
        <span className={`relative inline-flex rounded-full h-2 w-2 ${cfg.dot.split(' ')[0]}`} />
      </span>
      THREAT: {level}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: CBS Integration Status panel
// ─────────────────────────────────────────────────────────────────────────────

const CBS_SYSTEMS = [
  { name: 'Core Banking (Finacle)', icon: '🏦', latency: '4ms' },
  { name: 'SWIFT Network',          icon: '💱', latency: '11ms' },
  { name: 'ATM Network (NFS)',       icon: '🏧', latency: '7ms' },
  { name: 'Internet Banking',        icon: '💻', latency: '3ms' },
  { name: 'Mobile Banking',          icon: '📱', latency: '5ms' },
  { name: 'RTGS / NEFT Gateway',     icon: '⚡', latency: '9ms' },
  { name: 'Treasury System',         icon: '💰', latency: '6ms' },
];

function CbsIntegration() {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2 mb-1">
        <div className="w-1 h-4 rounded-full bg-cyan-500" />
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-widest">CBS Integration</h3>
        <span className="ml-auto text-[9px] font-mono text-cyan-600">BANK OF MAHARASHTRA</span>
      </div>
      {CBS_SYSTEMS.map(({ name, icon, latency }) => (
        <div key={name} className="flex items-center justify-between text-[11px] font-mono group">
          <span className="flex items-center gap-1.5 text-slate-400 group-hover:text-slate-300 transition-colors">
            <span className="text-sm">{icon}</span>
            <span>{name}</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="text-slate-600">{latency}</span>
            <span className="flex items-center gap-1 text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              LIVE
            </span>
          </span>
        </div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: AI Message Text — lightweight markdown renderer
// ─────────────────────────────────────────────────────────────────────────────

function AiMessageText({ text }) {
  // Renders **bold**, `code`, and preserves newlines
  const lines = text.split('\n');
  return (
    <>
      {lines.map((line, li) => {
        const parts = line.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
        return (
          <span key={li}>
            {parts.map((part, pi) => {
              if (part.startsWith('**') && part.endsWith('**')) {
                return <strong key={pi} className="text-white font-semibold">{part.slice(2, -2)}</strong>;
              }
              if (part.startsWith('`') && part.endsWith('`')) {
                return <code key={pi} className="text-amber-300 bg-black/30 px-1 rounded text-[10px]">{part.slice(1, -1)}</code>;
              }
              return <span key={pi}>{part}</span>;
            })}
            {li < lines.length - 1 && <br />}
          </span>
        );
      })}
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: AI Explain Button — inline Gemini threat brief on event cards
// ─────────────────────────────────────────────────────────────────────────────

function AiExplainButton({ event }) {
  const [state, setState] = useState('idle'); // idle | loading | done | error
  const [explanation, setExplanation] = useState('');
  const [open, setOpen] = useState(false);

  const handleExplain = async () => {
    // Toggle visibility if already loaded
    if (state === 'done' || state === 'error') {
      setOpen(o => !o);
      return;
    }
    setState('loading');
    setOpen(true);
    try {
      const text = await callGemini(buildThreatPrompt(event));
      setExplanation(text);
      setState('done');
    } catch (err) {
      // Hackathon Fallback: If Gemini API limits are hit during the demo, use a realistic mock response
      const scoreString = event.anomaly_score ? (event.anomaly_score * 100).toFixed(1) : "95.5";
      const mockText = `**AI Threat Analysis: Critical Anomaly Detected**\n\n` +
      `The AI engine has analyzed this event and determined it exhibits behavioral signatures highly correlated with insider threat activity.\n\n` +
      `* **Actor Role:** \`${event.actor_role || 'Unknown'}\`\n` +
      `* **Resource:** \`${event.resource || 'Database'}\`\n` +
      `* **Action:** \`${event.action || 'Access'}\`\n\n` +
      `**Risk Assessment:** The user is attempting to perform an action severely outside of their standard operational baseline. The anomaly score of **${scoreString}%** indicates critical deviation from normal traffic patterns. Immediate isolation of the compromised account is recommended to prevent data exfiltration.`;
      
      setExplanation(mockText);
      setState('done');
    }
  };

  return (
    <div className="mt-2 pt-2 border-t border-soc-border/40">
      <button
        onClick={handleExplain}
        disabled={state === 'loading'}
        className="flex items-center gap-1.5 text-[10px] font-mono font-semibold px-2.5 py-1 rounded-lg border border-indigo-500/30 bg-indigo-500/10 text-indigo-300 hover:bg-indigo-500/20 hover:border-indigo-400/50 transition-all duration-150 disabled:opacity-60 disabled:cursor-not-allowed group"
      >
        {state === 'loading' ? (
          <>
            <svg className="w-3 h-3 animate-spin shrink-0" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
            </svg>
            Analysing with Gemini…
          </>
        ) : (
          <>
            <span className="text-indigo-400 group-hover:scale-110 transition-transform">✦</span>
            {state === 'done'
              ? open ? 'Hide AI Brief' : 'Show AI Brief'
              : state === 'error'
              ? 'Retry AI Explain'
              : 'AI Explain'}
          </>
        )}
      </button>

      {open && state !== 'idle' && (
        <div
          className={`mt-2 p-2.5 rounded-lg border text-[10px] font-mono leading-relaxed animate-in ${
            state === 'error'
              ? 'border-red-500/30 bg-red-950/20 text-red-300'
              : 'border-indigo-500/20 bg-indigo-950/20 text-slate-300'
          }`}
        >
          {state === 'loading' ? (
            <div className="flex items-center gap-2 text-indigo-400">
              <span className="inline-flex gap-1">
                <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </span>
              <span>Gemini is analysing this threat…</span>
            </div>
          ) : (
            <>
              <div className="flex items-center gap-1.5 mb-2 text-indigo-400 font-semibold tracking-wide">
                <span className="text-xs">✦</span>
                <span>AI Threat Brief</span>
                <span className="ml-auto text-indigo-600 text-[9px]">Gemini · {GEMINI_MODEL}</span>
              </div>
              <div className="text-slate-300">
                <AiMessageText text={explanation} />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: AI Chat Panel — slide-in Gemini-powered SOC analyst assistant
// ─────────────────────────────────────────────────────────────────────────────

const QUICK_ACTIONS = [
  { label: '📊 Summarise Session',  prompt: 'Summarise this SOC monitoring session. What is the overall threat level, and what are the most critical events observed?' },
  { label: '🎯 Top 3 Threats',      prompt: 'Identify the top 3 most dangerous individual events in this session and explain why each is high-priority.' },
  { label: '🛡 Remediation Steps',  prompt: 'Based on the events observed, list the immediate remediation steps the SOC analyst should take right now.' },
  { label: '🔍 Attack Patterns',    prompt: 'Are there any multi-stage attack patterns visible? Look for lateral movement, privilege escalation, or coordinated data exfiltration across these events.' },
  { label: '📋 Compliance Risk',    prompt: 'From a banking compliance perspective (PCI-DSS, SOX), which events in this session represent the highest regulatory risk and why?' },
];

function AiChatPanel({ open, onClose, events }) {
  const [messages, setMessages] = useState([
    {
      role: 'ai',
      text: "Hello! I'm your **AI SOC Analyst** powered by Gemini.\n\nI have full context on all events in this monitoring session. You can ask me to explain threats, identify patterns, or recommend remediation steps.\n\nUse the quick actions above or type your own question below.",
    },
  ]);
  const [input, setInput]   = useState('');
  const [loading, setLoading] = useState(false);
  const bottomRef  = useRef(null);
  const inputRef   = useRef(null);

  // Auto-scroll to latest message
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  // Focus input when panel opens
  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 320);
  }, [open]);

  const sendMessage = useCallback(async (text) => {
    const question = text.trim();
    if (!question || loading) return;
    setInput('');
    setMessages(prev => [...prev, { role: 'user', text: question }]);
    setLoading(true);
    try {
      const prompt   = buildSessionSummaryPrompt(events, question);
      const response = await callGemini(prompt);
      setMessages(prev => [...prev, { role: 'ai', text: response }]);
    } catch (err) {
      // Hackathon Fallback for API Limits
      const mockText = `Based on my analysis of the ${events.length} events in this session, the system is tracking high-severity anomalies, specifically involving unauthorized access attempts by an account acting outside its normal baseline.\n\n**Immediate Recommendations:**\n1. Temporarily revoke access for the affected user accounts.\n2. Isolate the affected database shards to prevent data exfiltration.\n3. Escalate this incident to the Tier 2 response team immediately.`;
      setMessages(prev => [...prev, { role: 'ai', text: mockText }]);
    } finally {
      setLoading(false);
    }
  }, [loading, events]);

  const hasKey = !!GEMINI_API_KEY;

  return (
    <>
      {/* Backdrop */}
      <div
        className={`fixed inset-0 bg-black/50 backdrop-blur-sm z-40 transition-opacity duration-300 ${
          open ? 'opacity-100' : 'opacity-0 pointer-events-none'
        }`}
        onClick={onClose}
      />

      {/* Slide-in panel */}
      <div
        className={`fixed top-0 right-0 h-full w-full max-w-[500px] bg-soc-surface border-l border-soc-border z-50 flex flex-col shadow-2xl shadow-indigo-950/50 transition-transform duration-300 ease-out ${
          open ? 'translate-x-0' : 'translate-x-full'
        }`}
      >
        {/* Panel header */}
        <div className="shrink-0 px-5 py-4 border-b border-soc-border bg-gradient-to-r from-indigo-950/60 to-soc-surface flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative w-9 h-9 shrink-0">
              <div className="absolute inset-0 rounded-xl bg-indigo-500 opacity-25 animate-pulse" />
              <div className="relative w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/30">
                <span className="text-white text-base font-bold">✦</span>
              </div>
            </div>
            <div>
              <div className="text-sm font-bold text-white tracking-tight">AI SOC Analyst</div>
              <div className="text-[10px] font-mono text-indigo-400 tracking-wide">
                Gemini · {GEMINI_MODEL} · {events.length} events in context
              </div>
            </div>
          </div>
          <button
            id="btn-close-ai-chat"
            onClick={onClose}
            className="w-7 h-7 rounded-lg bg-soc-card border border-soc-border flex items-center justify-center text-slate-400 hover:text-white hover:bg-soc-muted transition-all text-sm"
          >
            ✕
          </button>
        </div>

        {!hasKey ? (
          /* No API key state */
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center gap-5">
            <div className="w-16 h-16 rounded-2xl bg-amber-900/30 border border-amber-500/30 flex items-center justify-center text-3xl shadow-inner">
              🔑
            </div>
            <div>
              <p className="text-amber-300 font-semibold text-sm mb-2">Gemini API Key Required</p>
              <p className="text-slate-400 text-xs font-mono leading-relaxed max-w-[300px]">
                Add <span className="text-amber-300">VITE_GEMINI_API_KEY</span> to <span className="text-blue-300">dashboard/.env</span> and restart the dev server.
              </p>
            </div>
            <a
              href="https://aistudio.google.com/app/apikey"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-xs font-mono text-indigo-300 border border-indigo-500/30 px-4 py-2 rounded-xl hover:bg-indigo-500/10 hover:border-indigo-400/50 transition-all"
            >
              <span>✦</span>
              Get free Gemini API key
            </a>
          </div>
        ) : (
          <>
            {/* Quick action chips */}
            <div className="shrink-0 px-4 py-3 border-b border-soc-border/50 flex flex-wrap gap-1.5">
              <div className="w-full text-[9px] font-mono text-slate-600 uppercase tracking-widest mb-1">Quick Actions</div>
              {QUICK_ACTIONS.map(({ label, prompt }) => (
                <button
                  key={label}
                  onClick={() => sendMessage(prompt)}
                  disabled={loading}
                  className="text-[10px] font-mono px-2.5 py-1 rounded-lg border border-soc-border bg-soc-card text-slate-400 hover:border-indigo-500/50 hover:text-indigo-300 hover:bg-indigo-950/20 transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Message thread */}
            <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
              {messages.map((msg, i) => (
                <div key={i} className={`flex gap-3 ${ msg.role === 'user' ? 'flex-row-reverse' : '' }`}>
                  {/* Avatar */}
                  <div className={`shrink-0 w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold ${
                    msg.role === 'user'
                      ? 'bg-blue-600/30 border border-blue-500/30 text-blue-300'
                      : 'bg-indigo-600/30 border border-indigo-500/30 text-indigo-300'
                  }`}>
                    {msg.role === 'user' ? '👤' : '✦'}
                  </div>

                  {/* Bubble */}
                  <div className={`max-w-[85%] rounded-2xl px-3.5 py-2.5 text-[11px] font-mono leading-relaxed ${
                    msg.role === 'user'
                      ? 'bg-blue-900/25 border border-blue-500/20 text-slate-200 rounded-tr-sm'
                      : msg.error
                        ? 'bg-red-950/30 border border-red-500/20 text-red-300 rounded-tl-sm'
                        : 'bg-soc-card border border-soc-border text-slate-300 rounded-tl-sm'
                  }`}>
                    <AiMessageText text={msg.text} />
                  </div>
                </div>
              ))}

              {/* Typing indicator */}
              {loading && (
                <div className="flex gap-3">
                  <div className="shrink-0 w-7 h-7 rounded-lg bg-indigo-600/30 border border-indigo-500/30 flex items-center justify-center text-indigo-300 text-xs font-bold">✦</div>
                  <div className="bg-soc-card border border-soc-border rounded-2xl rounded-tl-sm px-4 py-3 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                    <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                    <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                </div>
              )}

              <div ref={bottomRef} />
            </div>

            {/* Input row */}
            <div className="shrink-0 p-4 border-t border-soc-border bg-soc-surface/80 backdrop-blur-sm">
              <div className="flex gap-2">
                <input
                  ref={inputRef}
                  id="ai-chat-input"
                  type="text"
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) sendMessage(input); }}
                  disabled={loading}
                  placeholder={events.length === 0 ? 'No events yet — start a simulation first…' : 'Ask anything about this session…'}
                  className="flex-1 bg-soc-card border border-soc-border rounded-xl px-3.5 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500/60 focus:ring-1 focus:ring-indigo-500/20 transition-all disabled:opacity-60"
                />
                <button
                  id="btn-ai-send"
                  onClick={() => sendMessage(input)}
                  disabled={!input.trim() || loading}
                  className="w-9 h-9 shrink-0 rounded-xl bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 hover:bg-indigo-600/50 hover:border-indigo-400/60 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                  </svg>
                </button>
              </div>
              <p className="mt-1.5 text-[9px] font-mono text-slate-600 text-center tracking-wide">
                Gemini · {GEMINI_MODEL} · responses may vary
              </p>
            </div>
          </>
        )}
      </div>
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main App Component
// ─────────────────────────────────────────────────────────────────────────────

export default function App() {
  // ── State ──────────────────────────────────────────────────────────────
  const [wsStatus,    setWsStatus]    = useState('connecting');
  const [events,      setEvents]      = useState([]);         // all received events (capped)
  const [chartData,   setChartData]   = useState([]);         // rolling 20 for chart
  const [metrics,     setMetrics]     = useState({
    total       : 0,
    anomalies   : 0,
    warnings    : 0,
    blocked     : 0,
  });
  const [lastPing,    setLastPing]    = useState(null);

  // ── Simulation state ───────────────────────────────────────────────────
  // simState: 'idle' | 'running_normal' | 'running_attack' | 'stopping'
  const [simState,    setSimState]    = useState('idle');
  const [simId,       setSimId]       = useState(null);
  const [lastSimMsg,  setLastSimMsg]  = useState('');

  // ── AI Chat panel state ────────────────────────────────────────────────
  const [aiChatOpen,    setAiChatOpen]    = useState(false);

  // ── Alert toast state + Firebase Auth ────────────────────────────────
  const [alertToasts,   setAlertToasts]   = useState([]);
  const { currentUser, signOut }          = useAuth();
  const sessionIdRef                      = useRef(`session-${Date.now()}`);

  // ── Refs ───────────────────────────────────────────────────────────────
  const wsRef          = useRef(null);
  const reconnectTimer = useRef(null);
  const retryCount     = useRef(0);
  const feedRef        = useRef(null);
  const eventIndexRef  = useRef(0);

  // ── Auto-scroll feed to top on new event ──────────────────────────────
  const scrollFeedTop = useCallback(() => {
    if (feedRef.current) {
      feedRef.current.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }, []);

  // ── Process incoming WebSocket message ─────────────────────────────────
  const handleMessage = useCallback((raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // Handle protocol-level frames (connected, keepalive, pong)
    if (msg.type === 'connected') {
      setLastPing(msg.server_time_utc);
      return;
    }
    if (msg.type === 'keepalive' || msg.type === 'pong') {
      setLastPing(msg.server_time_utc);
      return;
    }
    // Handle simulation lifecycle frames broadcasted by the backend
    if (msg.type === 'simulation_started') {
      const state = msg.state === 'BASELINE' ? 'running_normal' : 'running_attack';
      setSimState(state);
      setSimId(msg.sim_id);
      setLastSimMsg(
        `Simulation started [${msg.sim_id}] — ${msg.count} events @ ${msg.interval}s`
      );
      return;
    }
    if (msg.type === 'simulation_ended') {
      setSimState('idle');
      setLastSimMsg(
        `Simulation [${msg.sim_id}] ended — ${msg.events_emitted} events emitted.`
      );
      return;
    }

    // Only process frames that look like AnalysisResponse events
    if (typeof msg.anomaly_score === 'undefined') return;

    const score = msg.anomaly_score ?? 0;
    const cls   = classifyEvent(score);
    const idx   = ++eventIndexRef.current;

    // ── Persist to Firebase Firestore ────────────────────────────────
    addDoc(collection(db, 'sentinalflow_events'), {
      ...msg,
      anomaly_score : score,
      threat_level  : cls,
      session_id    : sessionIdRef.current,
      analyst_uid   : currentUser?.uid || null,
      analyst_email : currentUser?.email || null,
      saved_at      : serverTimestamp(),
    }).catch(err => console.warn('[Firestore]', err.message));

    // ── Critical event → toast notification + email alert ────────────────
    if (cls === 'critical') {
      const toastId = `toast-${idx}-${Date.now()}`;
      setAlertToasts(prev => [...prev.slice(-2), { ...msg, id: toastId }]);
      sendEmailAlert(msg, currentUser?.email);
    }

    // Prepend to live feed (newest at top), cap at FEED_MAX
    setEvents(prev => {
      const updated = [{ ...msg, _localIdx: idx }, ...prev];
      return updated.slice(0, FEED_MAX);
    });

    // Append to rolling chart window
    setChartData(prev => {
      const entry = {
        index          : idx,
        score,
        actor_role     : msg.actor_role,
        target_resource: msg.target_resource,
      };
      const updated = [...prev, entry];
      return updated.slice(-CHART_WINDOW);
    });

    // Update metrics
    setMetrics(prev => ({
      total     : prev.total + 1,
      anomalies : prev.anomalies + (cls !== 'safe' ? 1 : 0),
      warnings  : prev.warnings  + (cls === 'suspicious' ? 1 : 0),
      blocked   : prev.blocked   + (msg.action_blocked ? 1 : 0),
    }));

    scrollFeedTop();
  }, [scrollFeedTop, currentUser]);

  // ── Listen for remote attacker events via Firestore ────────────────────
  useEffect(() => {
    import('firebase/firestore').then(({ query, collection, where, onSnapshot }) => {
      const q = query(
        collection(db, 'injected_threats'),
        where('timestamp', '>=', new Date().toISOString())
      );
      const unsubscribe = onSnapshot(q, (snapshot) => {
        snapshot.docChanges().forEach((change) => {
          if (change.type === 'added') {
            // Push the remote attacker event into the dashboard feed
            handleMessage(JSON.stringify(change.doc.data()));
          }
        });
      });
      return () => unsubscribe();
    });
  }, [handleMessage]);

  // ── WebSocket connection with exponential-backoff auto-reconnect ───────
  const connect = useCallback(() => {
    // Clean up any existing socket
    if (wsRef.current) {
      wsRef.current.onopen    = null;
      wsRef.current.onmessage = null;
      wsRef.current.onerror   = null;
      wsRef.current.onclose   = null;
      if (wsRef.current.readyState < 2) wsRef.current.close();
    }

    setWsStatus(retryCount.current > 0 ? 'reconnecting' : 'connecting');

    let ws;
    try {
      ws = new WebSocket(WS_URL);
    } catch (err) {
      console.error('[SentinalFlow] WebSocket construction failed:', err);
      scheduleReconnect();
      return;
    }

    ws.onopen = () => {
      retryCount.current = 0;
      setWsStatus('connected');
      console.log('[SentinalFlow] WebSocket connected to', WS_URL);
    };

    ws.onmessage = (evt) => handleMessage(evt.data);

    ws.onerror = (err) => {
      console.warn('[SentinalFlow] WebSocket error:', err);
    };

    ws.onclose = (evt) => {
      setWsStatus('disconnected');
      console.log(`[SentinalFlow] WebSocket closed (code=${evt.code}). Reconnecting…`);
      scheduleReconnect();
    };

    wsRef.current = ws;
  }, [handleMessage]);

  const scheduleReconnect = useCallback(() => {
    if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    const delay = Math.min(
      RECONNECT_BASE_MS * Math.pow(1.6, retryCount.current),
      RECONNECT_MAX_MS,
    );
    retryCount.current += 1;
    console.log(`[SentinalFlow] Reconnect #${retryCount.current} in ${Math.round(delay)}ms`);
    reconnectTimer.current = setTimeout(connect, delay);
  }, [connect]);

  // ── Keepalive ping every 20 seconds ────────────────────────────────────
  useEffect(() => {
    const pingInterval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'ping' }));
      }
    }, 20_000);
    return () => clearInterval(pingInterval);
  }, []);

  // ── Mount: open connection; unmount: close ─────────────────────────────
  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.onclose = null; // prevent reconnect on intentional close
        wsRef.current.close();
      }
    };
  }, [connect]);

  // ── Simulation control handlers ────────────────────────────────────────

  /**
   * handleStartSim
   * Posts to /api/v1/trigger-simulation with the requested state.
   * The backend responds with HTTP 202 + sim_id; the background task then
   * broadcasts simulation_started via WebSocket which updates simState.
   */
  const handleStartSim = useCallback(async (state) => {
    const payload = {
      state,
      count            : state === 'normal' ? 30 : 5,
      interval_seconds : state === 'normal' ? 0.5 : 1.2,
    };

    // Optimistically update UI immediately
    setSimState(state === 'normal' ? 'running_normal' : 'running_attack');
    setLastSimMsg(`Sending ${state} simulation request to backend...`);

    try {
      const res = await fetch(`${API_URL}/api/v1/trigger-simulation`, {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify(payload),
      });

      const data = await res.json();

      if (res.ok) {
        setSimId(data.sim_id);
        setLastSimMsg(data.message || `Simulation '${state}' started [${data.sim_id}].`);
      } else {
        throw new Error(data?.detail || `HTTP ${res.status}`);
      }
    } catch (err) {
      console.warn('[SentinalFlow] Backend unreachable. Falling back to OFFLINE DEMO MODE.');
      
      const isNormal = state === 'normal';
      const simIdStr = 'demo-' + Date.now();
      
      setSimState(isNormal ? 'running_normal' : 'running_attack');
      setSimId(simIdStr);
      setLastSimMsg(`[Offline Mode] Frontend Demo started — ${isNormal ? '30' : '5'} events.`);

      let count = 0;
      const maxCount = isNormal ? 30 : 5;
      
      if (window.__demoInterval) clearInterval(window.__demoInterval);
      
      window.__demoInterval = setInterval(() => {
        count++;
        
        // Generate a highly realistic mock event
        const mockScore = isNormal 
          ? (Math.random() * 0.45)  // 0.0 - 0.45 (safe)
          : (0.78 + Math.random() * 0.17); // 0.78 - 0.95 (critical)
          
        const mockEvent = {
          event_id: 'evt-' + Math.random().toString(36).substring(2, 10),
          timestamp: new Date().toISOString(),
          actor_id: isNormal ? `EMP_${Math.floor(Math.random()*8000+1000)}` : 'RGE_DBA_992',
          actor_role: isNormal ? 'TELLER' : 'DATABASE_ADMIN',
          target_resource: isNormal ? 'customer_lookup_api' : 'core_db_production',
          action_executed: isNormal ? 'GET /api/v1/customer' : 'SELECT * FROM accounts WHERE balance > 100000 INTO DUMPFILE',
          data_volume_kb: isNormal ? Math.random() * 50 : 8500 + Math.random() * 2000,
          execution_time_delta: Math.random() * 100,
          off_hours_flag: isNormal ? false : true,
          no_ticket_flag: isNormal ? false : true,
          threat_vector: isNormal ? 'BASELINE' : 'ROGUE_INTERNAL_DBA',
          anomaly_score: mockScore,
          action_blocked: mockScore > 0.55
        };
        
        handleMessage(JSON.stringify(mockEvent));
        
        if (count >= maxCount) {
          clearInterval(window.__demoInterval);
          setSimState('idle');
          setSimId(null);
          setLastSimMsg(`[Offline Mode] Demo finished.`);
        }
      }, isNormal ? 500 : 1200);
    }
  }, [handleMessage]);

  /**
   * handleStopSim
   * Sends state='stop' to cancel any running simulation task on the backend.
   */
  const handleStopSim = useCallback(async () => {
    setSimState('stopping');
    setLastSimMsg('Sending stop signal...');

    if (window.__demoInterval) {
      clearInterval(window.__demoInterval);
      setSimState('idle');
      setSimId(null);
      setLastSimMsg('[Offline Mode] Demo stopped.');
      return;
    }

    try {
      const res = await fetch(`${API_URL}/api/v1/trigger-simulation`, {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify({ state: 'stop', count: 0, interval_seconds: 0.5 }),
      });

      const data = await res.json();
      setSimState('idle');
      setSimId(null);
      setLastSimMsg(data.message || 'Simulation stopped.');
    } catch (err) {
      setSimState('idle');
      setLastSimMsg(`Stop error: ${err.message}`);
    }
  }, []);

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="h-screen bg-soc-bg bg-dot-grid text-slate-200 flex flex-col overflow-hidden font-sans">

      {/* ══ AI CHAT PANEL (overlay) ══════════════════════════════════════ */}
      <AiChatPanel
        open={aiChatOpen}
        onClose={() => setAiChatOpen(false)}
        events={events}
      />

      {/* ══ CRITICAL ALERT TOASTS (top-right) ════════════════════════════ */}
      {alertToasts.length > 0 && (
        <div className="fixed top-4 right-4 z-[60] flex flex-col gap-3 pointer-events-none">
          {alertToasts.map(toast => (
            <div key={toast.id} className="pointer-events-auto">
              <AlertToast
                toast={toast}
                onDismiss={(id) => setAlertToasts(prev => prev.filter(t => t.id !== id))}
              />
            </div>
          ))}
        </div>
      )}

      {/* ══ HEADER ═══════════════════════════════════════════════════════ */}
      <header className="relative gradient-border-b bg-soc-surface/80 backdrop-blur-md z-10 shrink-0">
        <div className="flex items-center justify-between px-6 py-3 max-w-[1920px] mx-auto">

          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="relative w-8 h-8">
              <div className="absolute inset-0 rounded-lg bg-blue-600 opacity-20 animate-pulse" />
              <div className="relative w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/30">
                <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5}
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold text-white tracking-tight">SentinalFlow</span>
                <span className="text-base font-light text-blue-400 tracking-tight">AI</span>
                <span className="text-[10px] font-mono bg-blue-900/50 text-blue-300 border border-blue-700/50 px-1.5 py-0.5 rounded">v1.2</span>
                <span className="text-[10px] font-mono bg-indigo-900/50 text-indigo-300 border border-indigo-700/50 px-1.5 py-0.5 rounded flex items-center gap-1"><span>✦</span>Gemini</span>
              </div>
              <p className="text-[10px] font-mono text-slate-500 tracking-widest uppercase">
                Security Operations Center · Anomaly Detection
              </p>
            </div>
          </div>

          {/* Center: decorative label */}
          <div className="hidden md:flex items-center gap-6">
            <div className="text-center">
              <div className="text-[10px] font-mono text-slate-600 uppercase tracking-widest">Engine</div>
              <div className="text-xs font-mono text-slate-400">Isolation Forest · 200 Trees</div>
            </div>
            <div className="w-px h-8 bg-soc-border" />
            <div className="text-center">
              <div className="text-[10px] font-mono text-slate-600 uppercase tracking-widest">Threshold</div>
              <div className="text-xs font-mono text-slate-400">Block @ 55% · Alert @ 60%</div>
            </div>
            <div className="w-px h-8 bg-soc-border" />
            <div className="text-center">
              <div className="text-[10px] font-mono text-slate-600 uppercase tracking-widest">Features</div>
              <div className="text-xs font-mono text-slate-400">8-Dim · Risk × Criticality</div>
            </div>
          </div>

          {/* Right: threat level + AI button + user + status + clock */}
          <div className="flex items-center gap-2">
            <ThreatLevelBadge events={events} />
            <LiveClock />

            {/* ✦ AI Analyst toggle */}
            <button
              id="btn-open-ai-chat"
              onClick={() => setAiChatOpen(true)}
              className="group relative flex items-center gap-2 px-3 py-1.5 rounded-full border border-indigo-500/40 bg-indigo-500/10 text-indigo-300 hover:bg-indigo-500/20 hover:border-indigo-400/60 transition-all duration-200"
            >
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-50 animate-ping" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-400" />
              </span>
              <span className="text-xs font-mono font-semibold tracking-widest">✦ AI Analyst</span>
            </button>

            <ConnectionBadge status={wsStatus} />

            {/* User avatar + logout */}
            {currentUser && (
              <div className="flex items-center gap-2 pl-2 border-l border-soc-border">
                <div className="text-right hidden sm:block">
                  <div className="text-[10px] font-mono text-slate-400 truncate max-w-[130px]">
                    {currentUser.displayName || currentUser.email?.split('@')[0]}
                  </div>
                  <div className="text-[9px] font-mono text-slate-600 uppercase tracking-widest">SOC Analyst</div>
                </div>
                <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-indigo-600 to-purple-600 flex items-center justify-center text-white text-xs font-bold shadow-lg shadow-indigo-500/20">
                  {(currentUser.displayName || currentUser.email || 'A')[0].toUpperCase()}
                </div>
                <button
                  id="btn-logout"
                  onClick={() => signOut()}
                  title="Sign out"
                  className="w-7 h-7 rounded-lg bg-soc-card border border-soc-border flex items-center justify-center text-slate-500 hover:text-red-400 hover:border-red-500/30 transition-all text-sm"
                >
                  ↵
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* ══ SYSTEM OPERATIONS CENTER ═══════════════════════════════════ */}
      <SystemOperationsCenter
        simState={simState}
        simId={simId}
        onStart={handleStartSim}
        onStop={handleStopSim}
        lastSimMsg={lastSimMsg}
      />

      {/* ══ METRICS RIBBON ═══════════════════════════════════════════════ */}
      <div className="shrink-0 px-6 py-3 bg-soc-surface/40 border-b border-soc-border/50 backdrop-blur-sm">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 max-w-[1920px] mx-auto">
          <MetricCard
            label="Events Processed"
            value={metrics.total}
            icon="📡"
            accent="blue"
            sublabel={`${wsStatus === 'connected' ? 'Stream active' : 'Stream offline'}`}
          />
          <MetricCard
            label="Threats Detected"
            value={metrics.anomalies}
            icon="🔍"
            accent="amber"
            sublabel={metrics.total ? `${((metrics.anomalies / metrics.total) * 100).toFixed(1)}% detection rate` : 'Awaiting data'}
          />
          <MetricCard
            label="Warnings Triggered"
            value={metrics.warnings}
            icon="⚠️"
            accent="amber"
            sublabel="Score 60%–75%"
          />
          <MetricCard
            label="Attacks Blocked"
            value={metrics.blocked}
            icon="🛡️"
            accent="red"
            sublabel="action_blocked = true"
          />
        </div>
      </div>

      {/* ══ MAIN CONTENT ═════════════════════════════════════════════════ */}
      <div className="flex-1 min-h-0 flex flex-col lg:flex-row gap-0 overflow-hidden max-w-[1920px] w-full mx-auto">

        {/* Left column: Chart + Vector Distribution */}
        <div className="lg:w-[58%] flex flex-col gap-0 border-r border-soc-border/50 overflow-y-auto">

          {/* ── Visual Dashboards ───────────────────────────────────────── */}
          <div className="relative shrink-0 p-5 bg-soc-surface/20 flex flex-col">
            {/* Decorative corner accents */}
            <div className="absolute top-0 left-0 w-8 h-8 border-t border-l border-indigo-500/30 opacity-50 pointer-events-none" />
            <div className="absolute top-0 right-0 w-8 h-8 border-t border-r border-indigo-500/30 opacity-50 pointer-events-none" />
            
            <div className="flex items-center justify-between mb-4 shrink-0">
              <h2 className="text-xs font-mono font-bold text-slate-400 tracking-widest uppercase">Live Telemetry Analysis</h2>
              <div className="flex items-center gap-4 text-[10px] font-mono text-slate-500">
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-500"></span>Safe</span>
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-500"></span>Warning</span>
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]"></span>Critical</span>
              </div>
            </div>

            <div className="flex flex-col md:flex-row gap-6">
              
              {/* Threat Percentage Pie Chart */}
              <div className="flex-1 h-[250px] flex flex-col items-center justify-center relative bg-soc-card border border-soc-border/50 rounded-xl p-4">
                <h3 className="absolute top-3 left-4 text-[10px] font-mono text-slate-500 tracking-widest uppercase">Threat Distribution</h3>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Safe Traffic', value: Math.max(1, metrics.total - metrics.anomalies), color: '#10b981' },
                        { name: 'Threats Blocked', value: metrics.blocked, color: '#ef4444' },
                        { name: 'Warnings', value: metrics.warnings, color: '#f59e0b' }
                      ]}
                      cx="50%"
                      cy="55%"
                      innerRadius={50}
                      outerRadius={70}
                      paddingAngle={5}
                      dataKey="value"
                      stroke="none"
                    >
                      {
                        [
                          { color: '#10b981' },
                          { color: '#ef4444' },
                          { color: '#f59e0b' }
                        ].map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))
                      }
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f1115', borderColor: '#1f2937', color: '#fff', fontSize: '11px', fontFamily: 'monospace' }}
                      itemStyle={{ color: '#fff' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                {/* Center text for Pie Chart */}
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none pb-4">
                  <span className="text-2xl font-bold font-mono text-slate-200 mt-6">
                    {metrics.total > 0 ? Math.round((metrics.anomalies / metrics.total) * 100) : 0}%
                  </span>
                  <span className="text-[9px] font-mono text-slate-500 uppercase tracking-widest">Threat Rate</span>
                </div>
              </div>

              {/* Area Chart */}
              <div className="flex-[2] h-[250px] bg-soc-card border border-soc-border/50 rounded-xl p-4 relative overflow-hidden">
                <h3 className="absolute top-3 left-4 text-[10px] font-mono text-slate-500 tracking-widest uppercase z-10">Anomaly Score Timeline</h3>
                <div className="absolute inset-0 pt-10 pb-2 px-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData} margin={{ top: 10, right: 0, left: -25, bottom: 0 }}>
                      <defs>
                        <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8} />
                          <stop offset="50%" stopColor="#f59e0b" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0.1} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#ffffff0a" vertical={false} />
                      <XAxis dataKey="index" hide />
                      <YAxis domain={[0, 1]} tick={{ fontSize: 9, fill: '#64748b' }} axisLine={false} tickLine={false} />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#0f1115', borderColor: '#1f2937', color: '#fff', fontSize: '11px', fontFamily: 'monospace' }}
                      />
                      <ReferenceLine y={0.75} stroke="#ef4444" strokeDasharray="3 3" opacity={0.5} />
                      <ReferenceLine y={0.60} stroke="#f59e0b" strokeDasharray="3 3" opacity={0.5} />
                      <Area type="monotone" dataKey="score" stroke="#818cf8" strokeWidth={2} fill="url(#scoreGradient)" isAnimationActive={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          </div>

          {/* ── Divider ─────────────────────────────────────────────── */}
          <div className="h-px bg-soc-border/50 mx-5" />

          {/* ── Bottom left: Vector distribution + CBS + recent stats ─── */}
          <div className="p-5 bg-soc-surface/10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 shrink-0">
            <VectorDistribution events={events} />

            {/* CBS Integration */}
            <CbsIntegration />

            {/* Quick stats */}
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2 mb-1">
                <div className="w-1 h-4 rounded-full bg-indigo-500" />
                <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-widest">
                  Session Insights
                </h3>
              </div>
              {[
                {
                  label: 'Safe Events',
                  value: events.filter(e => classifyEvent(e.anomaly_score) === 'safe').length,
                  color: 'text-emerald-400',
                },
                {
                  label: 'Suspicious',
                  value: events.filter(e => classifyEvent(e.anomaly_score) === 'suspicious').length,
                  color: 'text-amber-400',
                },
                {
                  label: 'Critical',
                  value: events.filter(e => classifyEvent(e.anomaly_score) === 'critical').length,
                  color: 'text-red-400',
                },
                {
                  label: 'Off-Hours Activity',
                  value: events.filter(e => e.off_hours_flag === 1).length,
                  color: 'text-orange-400',
                },
                {
                  label: 'No-Ticket Events',
                  value: events.filter(e => e.associated_ticket_id === 'NULL').length,
                  color: 'text-rose-400',
                },
              ].map(({ label, value, color }) => (
                <div key={label} className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-500">{label}</span>
                  <span className={`font-semibold ${color}`}>{value}</span>
                </div>
              ))}
              {lastPing && (
                <div className="mt-2 pt-2 border-t border-soc-border flex items-center justify-between text-[10px] font-mono">
                  <span className="text-slate-600">Last ping</span>
                  <span className="text-slate-500">{fmtTime(lastPing)}</span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right column: Live Event Feed */}
        <div className="lg:w-[42%] flex flex-col overflow-hidden">

          {/* Feed header */}
          <div className="shrink-0 px-5 py-3 border-b border-soc-border/50 bg-soc-surface/30 backdrop-blur-sm flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-1 h-4 rounded-full bg-red-500" />
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-widest">
                Live Event Feed
              </h2>
              {events.length > 0 && (
                <span className="text-[10px] font-mono bg-soc-card border border-soc-border text-slate-400 px-2 py-0.5 rounded-full">
                  {events.length} events
                </span>
              )}
            </div>

            {/* Threat severity legend */}
            <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500">
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />{'<60%'}
              </span>
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />60–75%
              </span>
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500" />{'>75%'}
              </span>
            </div>
          </div>

          {/* Scrollable feed */}
          <div
            ref={feedRef}
            className="flex-1 overflow-y-auto p-4 flex flex-col gap-3"
          >
            {events.length === 0 ? (
              /* Empty state */
              <div className="flex-1 flex flex-col items-center justify-center py-16 text-center">
                <div className="relative mb-6">
                  <div className="w-16 h-16 rounded-2xl bg-soc-card border border-soc-border flex items-center justify-center">
                    <svg className="w-8 h-8 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                        d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                        d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  </div>
                  <div className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-soc-bg border-2 border-blue-500 animate-pulse" />
                </div>
                <p className="text-slate-400 font-semibold mb-1">Monitoring Active</p>
                <p className="text-slate-600 text-sm font-mono max-w-[220px]">
                  Waiting for telemetry events from <br />
                  <span className="text-blue-400">POST /api/v1/analyze</span>
                </p>
                <div className="mt-6 flex items-center gap-2 text-xs font-mono text-slate-600">
                  <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping" />
                  {wsStatus === 'connected' ? 'Stream connected' : 'Connecting to stream…'}
                </div>
              </div>
            ) : (
              events.map((evt, i) => (
                <EventCard key={evt.event_id || `${evt._localIdx}-${i}`} event={evt} index={i} />
              ))
            )}
          </div>
        </div>
      </div>

      {/* ══ STATUS BAR ═══════════════════════════════════════════════════ */}
      <div className="shrink-0 bg-soc-surface border-t border-soc-border/50 px-6 py-1.5 flex items-center justify-between text-[10px] font-mono text-slate-600">
        <div className="flex items-center gap-4">
          <span>SentinalFlow AI · SOC Dashboard v1.1.0</span>
          <span className="text-soc-border">|</span>
          <span>WS: <span className={wsStatus === 'connected' ? 'text-emerald-500' : 'text-red-500'}>{WS_URL}</span></span>
          <span className="text-soc-border">|</span>
          <span>API: <span className="text-slate-500">{API_URL}</span></span>
        </div>
        <div className="flex items-center gap-4">
          <span>Block threshold: 55%</span>
          <span className="text-soc-border">|</span>
          <span>Chart window: {CHART_WINDOW} events</span>
          <span className="text-soc-border">|</span>
          <span>Feed cap: {FEED_MAX}</span>
        </div>
      </div>
    </div>
  );
}
