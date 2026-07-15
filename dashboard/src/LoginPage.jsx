/**
 * LoginPage.jsx — SentinalFlow AI
 * Beautiful SOC-themed login / sign-up / password-reset page
 * Branded for Bank of Maharashtra
 */
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from './AuthContext';

// ─── Animated background particles ──────────────────────────────────────────
function Particle({ style }) {
  return (
    <div
      className="absolute rounded-full pointer-events-none"
      style={{
        background: 'radial-gradient(circle, rgba(99,102,241,0.6) 0%, transparent 70%)',
        ...style,
      }}
    />
  );
}

// ─── Feature list item ───────────────────────────────────────────────────────
function Feature({ icon, title, desc, delay }) {
  return (
    <div
      className="flex items-start gap-3 opacity-0"
      style={{ animation: `fadeSlideIn 0.6s ease forwards ${delay}` }}
    >
      <div className="shrink-0 w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-base mt-0.5">
        {icon}
      </div>
      <div>
        <div className="text-sm font-semibold text-slate-200">{title}</div>
        <div className="text-xs text-slate-500 mt-0.5 leading-relaxed">{desc}</div>
      </div>
    </div>
  );
}

// ─── Input field ─────────────────────────────────────────────────────────────
function InputField({ label, type, value, onChange, placeholder, icon, autoComplete }) {
  const [focused, setFocused] = useState(false);
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-widest">
        {label}
      </label>
      <div
        className={`relative flex items-center gap-2 px-3.5 py-3 rounded-xl border bg-soc-card transition-all duration-200 ${
          focused
            ? 'border-indigo-500/70 shadow-[0_0_0_3px_rgba(99,102,241,0.15)]'
            : 'border-soc-border hover:border-soc-muted'
        }`}
      >
        <span className="text-base shrink-0">{icon}</span>
        <input
          type={type}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          autoComplete={autoComplete}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          className="flex-1 bg-transparent text-sm font-mono text-slate-200 placeholder-slate-600 outline-none"
        />
      </div>
    </div>
  );
}

// ─── Main Login Page ──────────────────────────────────────────────────────────
export default function LoginPage() {
  const [mode, setMode]           = useState('signin'); // 'signin' | 'signup' | 'reset'
  const [email, setEmail]         = useState('');
  const [password, setPassword]   = useState('');
  const [name, setName]           = useState('');
  const [error, setError]         = useState('');
  const [loading, setLoading]     = useState(false);
  const [resetSent, setResetSent] = useState(false);
  const [shake, setShake]         = useState(false);

  const { signIn, signUp, resetPassword } = useAuth();
  const navigate = useNavigate();

  // Inject keyframe animations into the document
  useEffect(() => {
    const style = document.createElement('style');
    style.textContent = `
      @keyframes fadeSlideIn {
        from { opacity: 0; transform: translateX(-20px); }
        to   { opacity: 1; transform: translateX(0); }
      }
      @keyframes floatUp {
        0%   { transform: translateY(0px) scale(1); opacity: 0.4; }
        50%  { transform: translateY(-30px) scale(1.1); opacity: 0.7; }
        100% { transform: translateY(0px) scale(1); opacity: 0.4; }
      }
      @keyframes shakeError {
        0%,100% { transform: translateX(0); }
        20%     { transform: translateX(-8px); }
        40%     { transform: translateX(8px); }
        60%     { transform: translateX(-5px); }
        80%     { transform: translateX(5px); }
      }
      @keyframes scanDown {
        0%   { top: -2px; }
        100% { top: 100%; }
      }
      @keyframes pulseRing {
        0%   { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(99,102,241,0.5); }
        70%  { transform: scale(1); box-shadow: 0 0 0 12px rgba(99,102,241,0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(99,102,241,0); }
      }
      @keyframes gradientShift {
        0%   { background-position: 0% 50%; }
        50%  { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
      }
      .logo-pulse { animation: pulseRing 2s ease-in-out infinite; }
      .gradient-text {
        background: linear-gradient(135deg, #6366f1, #8b5cf6, #a78bfa);
        background-clip: text;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-size: 200%;
        animation: gradientShift 3s ease infinite;
      }
      .scan-line-anim {
        position: absolute;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, rgba(99,102,241,0.5), transparent);
        animation: scanDown 3s linear infinite;
        pointer-events: none;
      }
    `;
    document.head.appendChild(style);
    return () => document.head.removeChild(style);
  }, []);

  const fireError = (msg) => {
    setError(msg);
    setShake(true);
    setTimeout(() => setShake(false), 600);
  };

  const ERROR_MAP = {
    'auth/user-not-found':       'No account found with this email.',
    'auth/wrong-password':       'Incorrect password. Please try again.',
    'auth/email-already-in-use': 'This email is already registered.',
    'auth/weak-password':        'Password must be at least 6 characters.',
    'auth/invalid-email':        'Please enter a valid email address.',
    'auth/invalid-credential':   'Invalid email or password.',
    'auth/too-many-requests':    'Too many attempts. Please wait and try again.',
    'auth/network-request-failed': 'Network error. Check your connection.',
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!email.trim()) return fireError('Email is required.');
    if (mode !== 'reset' && !password) return fireError('Password is required.');

    setLoading(true);
    try {
      if (mode === 'signin') {
        await signIn(email.trim(), password);
        navigate('/');
      } else if (mode === 'signup') {
        if (!name.trim()) { setLoading(false); return fireError('Full name is required.'); }
        await signUp(email.trim(), password, name.trim());
        navigate('/');
      } else {
        await resetPassword(email.trim());
        setResetSent(true);
      }
    } catch (err) {
      fireError(ERROR_MAP[err.code] || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#050810] flex overflow-hidden relative">

      {/* ── Animated dot grid background ── */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage: 'radial-gradient(rgba(99,102,241,0.12) 1px, transparent 1px)',
          backgroundSize: '28px 28px',
        }}
      />

      {/* ── Floating ambient glows ── */}
      <Particle style={{ width: 400, height: 400, top: '-100px', left: '-80px', animation: 'floatUp 8s ease-in-out infinite', opacity: 0.3 }} />
      <Particle style={{ width: 300, height: 300, bottom: '-60px', right: '30%', animation: 'floatUp 10s ease-in-out infinite 2s', opacity: 0.25 }} />
      <Particle style={{ width: 200, height: 200, top: '40%', right: '-40px', animation: 'floatUp 7s ease-in-out infinite 4s', opacity: 0.2, background: 'radial-gradient(circle, rgba(168,85,247,0.5) 0%, transparent 70%)' }} />

      {/* ══════════════════════════════════════════════════════
          LEFT PANEL — Branding & Features
      ══════════════════════════════════════════════════════ */}
      <div className="hidden lg:flex lg:w-[52%] flex-col justify-between p-12 relative z-10">

        {/* Top: Logo + Bank name */}
        <div
          className="flex items-center gap-4 opacity-0"
          style={{ animation: 'fadeSlideIn 0.5s ease forwards 0.1s' }}
        >
          {/* Shield logo */}
          <div className="logo-pulse relative w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-600 to-purple-700 flex items-center justify-center shadow-xl shadow-indigo-500/30">
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <div className="text-xl font-bold text-white tracking-tight">
              SentinalFlow <span className="text-indigo-400">AI</span>
            </div>
            <div className="text-xs font-mono text-slate-500 tracking-widest uppercase">
              Bank of Maharashtra · Security Operations
            </div>
          </div>
        </div>

        {/* Center: Headline + features */}
        <div className="space-y-10">
          <div>
            <div
              className="text-4xl font-bold leading-tight mb-4 opacity-0"
              style={{ animation: 'fadeSlideIn 0.6s ease forwards 0.2s' }}
            >
              <span className="text-white">Protecting Banking</span>
              <br />
              <span className="gradient-text">Operations with AI</span>
            </div>
            <p
              className="text-slate-400 text-sm leading-relaxed max-w-[380px] opacity-0"
              style={{ animation: 'fadeSlideIn 0.6s ease forwards 0.35s' }}
            >
              Real-time insider threat detection powered by machine learning.
              Monitor every privileged action. Catch rogue employees before damage is done.
            </p>
          </div>

          <div className="space-y-5">
            <Feature icon="🔍" title="Real-time Anomaly Detection" desc="Isolation Forest ML scores every employee action in milliseconds, 24/7." delay="0.45s" />
            <Feature icon="🤖" title="Gemini AI Threat Analyst" desc="Get instant natural-language explanations and remediation advice for every alert." delay="0.55s" />
            <Feature icon="🛡️" title="Automatic Session Blocking" desc="Actions scoring above threshold are automatically blocked and the session revoked." delay="0.65s" />
            <Feature icon="🏦" title="Core Banking Integration" desc="Monitors Finacle CBS, SWIFT, ATM network, RTGS/NEFT gateway and more." delay="0.75s" />
            <Feature icon="📋" title="PCI-DSS & RBI Compliance" desc="Every event logged to Firebase for audit trail and regulatory reporting." delay="0.85s" />
          </div>
        </div>

        {/* Bottom: Stats */}
        <div
          className="flex items-center gap-8 opacity-0"
          style={{ animation: 'fadeSlideIn 0.6s ease forwards 0.9s' }}
        >
          {[
            { val: '< 30s',  label: 'Threat Detection' },
            { val: '8',      label: 'ML Features' },
            { val: '4',      label: 'Threat Vectors' },
            { val: '99.9%',  label: 'Uptime SLA' },
          ].map(({ val, label }) => (
            <div key={label} className="text-center">
              <div className="text-lg font-bold font-mono text-indigo-400">{val}</div>
              <div className="text-[10px] font-mono text-slate-600 uppercase tracking-widest">{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════
          RIGHT PANEL — Login Card
      ══════════════════════════════════════════════════════ */}
      <div className="flex-1 flex items-center justify-center p-6 relative z-10">
        <div className="w-full max-w-[420px]">

          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 mb-8">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-600 to-purple-700 flex items-center justify-center shadow-lg shadow-indigo-500/30">
              <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <div className="text-base font-bold text-white">SentinalFlow AI</div>
              <div className="text-[10px] text-slate-500 font-mono">Bank of Maharashtra</div>
            </div>
          </div>

          {/* Card */}
          <div
            className="relative rounded-2xl border border-soc-border bg-soc-surface/80 backdrop-blur-xl p-8 shadow-2xl shadow-black/60 overflow-hidden"
            style={{ animation: 'shakeError 0.5s ease', animationPlayState: shake ? 'running' : 'paused' }}
          >
            {/* Scan line */}
            <div className="scan-line-anim" />

            {/* Corner accent */}
            <div className="absolute top-0 left-0 w-20 h-20 rounded-tl-2xl border-t-2 border-l-2 border-indigo-500/30 pointer-events-none" />
            <div className="absolute bottom-0 right-0 w-20 h-20 rounded-br-2xl border-b-2 border-r-2 border-indigo-500/30 pointer-events-none" />

            {/* Header */}
            <div className="mb-7">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-mono text-indigo-400 font-semibold tracking-widest uppercase">
                  {mode === 'signin' ? 'SOC Analyst Portal' : mode === 'signup' ? 'Create Account' : 'Password Reset'}
                </span>
              </div>
              <h1 className="text-2xl font-bold text-white">
                {mode === 'signin'
                  ? 'Sign in to Dashboard'
                  : mode === 'signup'
                  ? 'Register New Analyst'
                  : 'Reset Your Password'}
              </h1>
              <p className="text-xs text-slate-500 font-mono mt-1">
                {mode === 'signin'
                  ? 'Authorized personnel only · All access is logged'
                  : mode === 'signup'
                  ? 'Access will be subject to SOC audit trail'
                  : 'Enter your email to receive a reset link'}
              </p>
            </div>

            {/* Reset success state */}
            {resetSent ? (
              <div className="text-center py-6">
                <div className="text-4xl mb-3">📧</div>
                <p className="text-emerald-400 font-semibold mb-1">Reset link sent!</p>
                <p className="text-slate-400 text-xs font-mono mb-6">Check your email inbox and follow the instructions.</p>
                <button
                  onClick={() => { setMode('signin'); setResetSent(false); }}
                  className="text-indigo-400 text-xs font-mono hover:text-indigo-300 transition-colors"
                >
                  ← Back to Sign In
                </button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-4">

                {/* Name field (signup only) */}
                {mode === 'signup' && (
                  <InputField
                    label="Full Name"
                    type="text"
                    value={name}
                    onChange={e => setName(e.target.value)}
                    placeholder="e.g. Aryan Sharma"
                    icon="👤"
                    autoComplete="name"
                  />
                )}

                {/* Email */}
                <InputField
                  label="Email Address"
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="analyst@bankofmaharashtra.com"
                  icon="✉️"
                  autoComplete="email"
                />

                {/* Password */}
                {mode !== 'reset' && (
                  <InputField
                    label="Password"
                    type="password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    placeholder={mode === 'signup' ? 'Min. 6 characters' : '••••••••'}
                    icon="🔒"
                    autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
                  />
                )}

                {/* Error message */}
                {error && (
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-red-500/30 bg-red-950/20 text-red-400 text-xs font-mono">
                    <span>⚠</span>
                    <span>{error}</span>
                  </div>
                )}

                {/* Submit button */}
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full relative overflow-hidden flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-mono font-bold text-sm tracking-wide bg-gradient-to-r from-indigo-600 to-purple-600 text-white shadow-lg shadow-indigo-500/25 hover:shadow-indigo-500/40 hover:scale-[1.01] active:scale-[0.99] transition-all duration-200 disabled:opacity-60 disabled:cursor-not-allowed disabled:hover:scale-100"
                >
                  {/* Shimmer sweep */}
                  <span className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/10 to-white/0 translate-x-[-100%] hover:translate-x-[100%] transition-transform duration-700 pointer-events-none" />

                  {loading ? (
                    <>
                      <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                      </svg>
                      {mode === 'reset' ? 'Sending…' : 'Authenticating…'}
                    </>
                  ) : (
                    <>
                      {mode === 'signin' ? '🔐 Sign In to Dashboard' : mode === 'signup' ? '✦ Create SOC Account' : '📧 Send Reset Link'}
                    </>
                  )}
                </button>

                {/* Mode toggles */}
                <div className="flex items-center justify-between pt-1">
                  {mode === 'signin' && (
                    <>
                      <button type="button" onClick={() => { setMode('reset'); setError(''); }}
                        className="text-[11px] font-mono text-slate-500 hover:text-indigo-400 transition-colors">
                        Forgot password?
                      </button>
                      <button type="button" onClick={() => { setMode('signup'); setError(''); }}
                        className="text-[11px] font-mono text-slate-500 hover:text-indigo-400 transition-colors">
                        New analyst? Register →
                      </button>
                    </>
                  )}
                  {(mode === 'signup' || mode === 'reset') && (
                    <button type="button" onClick={() => { setMode('signin'); setError(''); }}
                      className="text-[11px] font-mono text-slate-500 hover:text-indigo-400 transition-colors">
                      ← Back to Sign In
                    </button>
                  )}
                </div>
              </form>
            )}
          </div>

          {/* Footer */}
          <p className="text-center text-[10px] font-mono text-slate-700 mt-5">
            SentinalFlow AI · Bank of Maharashtra · All access is monitored & logged
          </p>
        </div>
      </div>
    </div>
  );
}
