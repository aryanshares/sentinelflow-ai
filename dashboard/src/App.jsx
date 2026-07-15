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
  defs,
  linearGradient,
  stop,
} from 'recharts';

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

function AnomalyChart({ chartData }) {
  const isEmpty = !chartData || chartData.length === 0;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="w-1 h-4 rounded-full bg-blue-500" />
          <h2 className="text-sm font-semibold text-slate-200 tracking-wide uppercase">
            Anomaly Score Timeline
          </h2>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span className="text-slate-400">Safe</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-500" />
            <span className="text-slate-400">Suspicious</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500" />
            <span className="text-slate-400">Critical</span>
          </span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-500">
            Last {Math.min(chartData.length, CHART_WINDOW)} events
          </span>
        </div>
      </div>

      {isEmpty ? (
        <div className="flex-1 flex flex-col items-center justify-center text-slate-600 gap-3">
          <svg className="w-12 h-12 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1}
              d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
          </svg>
          <p className="text-sm font-mono">Awaiting telemetry events…</p>
        </div>
      ) : (
        <div className="flex-1 min-h-0">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
              <defs>
                {/* Gradient fill: green at bottom, transitions to red at top */}
                <linearGradient id="scoreGradient" x1="0" y1="1" x2="0" y2="0">
                  <stop offset="0%"   stopColor="#10b981" stopOpacity={0.6} />
                  <stop offset="60%"  stopColor="#f59e0b" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#ef4444" stopOpacity={0.7} />
                </linearGradient>
                <linearGradient id="strokeGradient" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%"   stopColor="#3b82f6" />
                  <stop offset="100%" stopColor="#6366f1" />
                </linearGradient>
                {/* Glow filter for the line */}
                <filter id="lineGlow">
                  <feGaussianBlur stdDeviation="2" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              <CartesianGrid
                strokeDasharray="3 3"
                stroke="rgba(255,255,255,0.04)"
                vertical={false}
              />

              <XAxis
                dataKey="index"
                tick={{ fill: '#475569', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                tickLine={false}
                axisLine={{ stroke: '#1e2640' }}
                label={{ value: 'Event #', position: 'insideBottomRight', offset: -4, fill: '#334155', fontSize: 10 }}
              />

              <YAxis
                domain={[0, 1]}
                tickFormatter={v => `${(v * 100).toFixed(0)}%`}
                tick={{ fill: '#475569', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                tickLine={false}
                axisLine={false}
                ticks={[0, 0.25, 0.50, 0.75, 1.0]}
              />

              <Tooltip content={<ChartTooltip />} />

              {/* Reference lines for thresholds */}
              <ReferenceLine
                y={THRESHOLD_SAFE}
                stroke="rgba(245,158,11,0.35)"
                strokeDasharray="4 4"
                label={{ value: 'WARN', position: 'right', fill: '#f59e0b', fontSize: 9, fontFamily: 'JetBrains Mono' }}
              />
              <ReferenceLine
                y={THRESHOLD_SUSPICIOUS}
                stroke="rgba(239,68,68,0.35)"
                strokeDasharray="4 4"
                label={{ value: 'CRIT', position: 'right', fill: '#ef4444', fontSize: 9, fontFamily: 'JetBrains Mono' }}
              />

              <Area
                type="monotone"
                dataKey="score"
                stroke="url(#strokeGradient)"
                strokeWidth={2}
                fill="url(#scoreGradient)"
                fillOpacity={0.25}
                dot={(props) => {
                  const { cx, cy, payload } = props;
                  const cls = classifyEvent(payload.score);
                  const colors = { safe: '#10b981', suspicious: '#f59e0b', critical: '#ef4444' };
                  return (
                    <circle
                      key={payload.index}
                      cx={cx} cy={cy} r={4}
                      fill={colors[cls]}
                      stroke="#050810"
                      strokeWidth={1.5}
                    />
                  );
                }}
                activeDot={{ r: 6, stroke: '#3b82f6', strokeWidth: 2, fill: '#1e40af' }}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

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
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-component: Simulation Control Center
// ─────────────────────────────────────────────────────────────────────────────

/**
 * SimulationControlCenter
 * ───────────────────────
 * Renders a high-visibility control strip with two action buttons:
 *   • Start Baseline Operations  → POST {state:'normal', count:30}
 *   • Inject Adversarial Attack  → POST {state:'attack', count:5}
 * Plus a Stop button to cancel any running simulation.
 *
 * Props
 * ─────
 *   simState   : 'idle' | 'running_normal' | 'running_attack' | 'stopping'
 *   simId      : string | null  — sim_id returned by the backend
 *   onStart    : (state:'normal'|'attack') => void
 *   onStop     : () => void
 *   lastSimMsg : string  — last status message from the backend
 */
function SimulationControlCenter({ simState, simId, onStart, onStop, lastSimMsg }) {
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
                Simulation Control Center
              </h2>
              <p className="text-[10px] font-mono text-slate-500 mt-0.5">
                Fire internal telemetry simulations directly against the live AI engine
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
                {isNormal ? 'RUNNING...' : 'FIRE SIMULATION'}
              </span>
              <span>Start Baseline Operations</span>
            </span>

            {isNormal && (
              <svg className="w-4 h-4 animate-spin ml-1 text-emerald-400" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
              </svg>
            )}
          </button>

          {/* INJECT ATTACK */}
          <button
            id="btn-inject-attack"
            onClick={() => onStart('attack')}
            disabled={isRunning || isStopping}
            className={`
              group relative flex items-center gap-2.5 px-5 py-2.5 rounded-xl
              font-mono font-bold text-sm tracking-wide
              transition-all duration-200 overflow-hidden
              border shadow-lg
              ${ isAttack
                ? 'bg-red-600/30 border-red-500/60 text-red-300 cursor-not-allowed opacity-80'
                : (isRunning || isStopping)
                  ? 'bg-soc-card border-soc-border text-slate-600 cursor-not-allowed opacity-50'
                  : 'bg-red-600/20 border-red-500/40 text-red-300 hover:bg-red-600/35 hover:border-red-400/70 hover:shadow-red-500/25 hover:scale-[1.02] active:scale-[0.98] cursor-pointer'
              }
            `}
          >
            <span className="absolute inset-0 bg-gradient-to-r from-red-500/0 via-red-400/10 to-red-500/0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-700 pointer-events-none" />

            <span className={`w-2 h-2 rounded-full ${
              isAttack ? 'bg-red-400 animate-ping' : 'bg-red-500/70'
            }`} />

            <span className="flex flex-col items-start leading-none gap-0.5">
              <span className="text-[11px] text-red-400/70 font-normal">
                {isAttack ? 'INJECTING...' : 'EMULATE ADVERSARY'}
              </span>
              <span>Inject Adversarial Attack</span>
            </span>

            {isAttack && (
              <svg className="w-4 h-4 animate-spin ml-1 text-red-400" fill="none" viewBox="0 0 24 24">
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
            <span>{isStopping ? 'Stopping…' : 'Stop'}</span>
          </button>

          {/* Spacer + config hint */}
          <div className="ml-auto flex items-center gap-4 text-[10px] font-mono text-slate-600">
            <span>Normal: 30 events @ 0.5s</span>
            <span className="text-soc-border">|</span>
            <span>Attack: 5 events @ 1.2s</span>
          </div>
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
  }, [scrollFeedTop]);

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
        // Backend returned an error (e.g. 409 conflict, 503 no model)
        setSimState('idle');
        const detail = data?.detail || `HTTP ${res.status}`;
        setLastSimMsg(`ERROR: ${detail}`);
        console.warn('[SentinalFlow] trigger-simulation error:', detail);
      }
    } catch (err) {
      setSimState('idle');
      setLastSimMsg(`Network error: ${err.message}. Is the backend reachable?`);
      console.error('[SentinalFlow] fetch error:', err);
    }
  }, []);

  /**
   * handleStopSim
   * Sends state='stop' to cancel any running simulation task on the backend.
   */
  const handleStopSim = useCallback(async () => {
    setSimState('stopping');
    setLastSimMsg('Sending stop signal to backend...');

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
      console.error('[SentinalFlow] stop error:', err);
    }
  }, []);

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-soc-bg bg-dot-grid text-slate-200 flex flex-col overflow-hidden font-sans">

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
                <span className="text-[10px] font-mono bg-blue-900/50 text-blue-300 border border-blue-700/50 px-1.5 py-0.5 rounded">v1.1</span>
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

          {/* Right: status + clock */}
          <div className="flex items-center gap-3">
            <LiveClock />
            <ConnectionBadge status={wsStatus} />
          </div>
        </div>
      </header>

      {/* ══ SIMULATION CONTROL CENTER ══════════════════════════════════ */}
      <SimulationControlCenter
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
        <div className="lg:w-[58%] flex flex-col gap-0 border-r border-soc-border/50 overflow-hidden">

          {/* ── Area Chart ──────────────────────────────────────────── */}
          <div className="relative flex-1 min-h-0 p-5 bg-soc-surface/20">
            {/* Decorative corner accents */}
            <div className="absolute top-0 left-0 w-8 h-8 border-t-2 border-l-2 border-blue-500/30 rounded-tl-xl" />
            <div className="absolute bottom-0 right-0 w-8 h-8 border-b-2 border-r-2 border-blue-500/30 rounded-br-xl" />
            <AnomalyChart chartData={chartData} />
          </div>

          {/* ── Divider ─────────────────────────────────────────────── */}
          <div className="h-px bg-soc-border/50 mx-5" />

          {/* ── Bottom left: Vector distribution + recent stats ──────── */}
          <div className="p-5 bg-soc-surface/10 grid grid-cols-1 sm:grid-cols-2 gap-6 shrink-0">
            <VectorDistribution events={events} />

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
