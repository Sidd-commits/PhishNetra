import React, { useState } from 'react';
import {
  KeyRound,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Copy,
  Terminal,
  Activity,
  Layers,
  ArrowRight
} from 'lucide-react';
import { api } from '../services/api';
import { FIDO2AssessmentResult } from '@phishnetra/shared';

export const FIDO2GuardPage: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState<string>('https://login.microsoft.com-evilginx-proxy.net/auth');
  const [claimedBrand, setClaimedBrand] = useState<string>('microsoft');
  const [authProtocol, setAuthProtocol] = useState<string>('WEBAUTHN_FIDO2');
  const [assessment, setAssessment] = useState<FIDO2AssessmentResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [copiedSnippet, setCopiedSnippet] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleEvaluate = async (
    overrideUrl?: string,
    overrideBrand?: string,
    overrideProtocol?: string
  ) => {
    const url = overrideUrl || targetUrl;
    const brand = overrideBrand || claimedBrand;
    const protocol = (overrideProtocol || authProtocol) as any;

    if (!url.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const res = await api.evaluateFIDO2Guard({
        targetUrl: url,
        claimedBrand: brand,
        authProtocol: protocol
      });
      setAssessment(res);
    } catch (err: any) {
      setError(err?.response?.data?.message || err.message || 'Failed to evaluate FIDO2 origin binding');
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (url: string, brand: string, protocol: string) => {
    setTargetUrl(url);
    setClaimedBrand(brand);
    setAuthProtocol(protocol);
    handleEvaluate(url, brand, protocol);
  };

  const handleCopySnippet = () => {
    if (assessment?.webauthnPolicyEnforcementSnippet) {
      navigator.clipboard.writeText(assessment.webauthnPolicyEnforcementSnippet);
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 2500);
    }
  };

  return (
    <div className="min-w-0 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-emerald-950/40 to-slate-900 border border-slate-800 p-6 sm:p-8">
        <div className="space-y-2">
          <div className="flex items-center space-x-2.5">
            <span className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <KeyRound className="w-5 h-5 animate-pulse" />
            </span>
            <span className="text-xs font-mono font-semibold tracking-wider text-emerald-400 uppercase">
              Milestone 20 • Cryptographic Origin Anchoring
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            FIDO2 / WebAuthn Phishing-Resistant MFA Credential Guard
          </h1>
          <p className="text-sm text-slate-400 max-w-2xl">
            Simulate and verify WebAuthn clientDataJSON cryptographic origin binding against Adversary-in-the-Middle (AiTM)
            reverse proxies (Evilginx2, Modlishka) and validate organizational Passkey immunity.
          </p>
        </div>

        {/* Input Parameters Form */}
        <div className="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="sm:col-span-2 space-y-1">
            <label className="text-[11px] font-mono text-slate-400 uppercase">Target Login Portal / Proxy URL</label>
            <input
              type="text"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              placeholder="e.g. https://login.microsoft.com-evilginx-proxy.net/auth"
              className="w-full rounded-xl bg-slate-950/80 border border-slate-800 px-3.5 py-2.5 text-xs text-white font-mono placeholder-slate-600 focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-mono text-slate-400 uppercase">Claimed Brand IDP</label>
            <select
              value={claimedBrand}
              onChange={e => setClaimedBrand(e.target.value)}
              className="w-full rounded-xl bg-slate-950/80 border border-slate-800 px-3 py-2.5 text-xs text-white focus:outline-none focus:border-emerald-500 transition-colors"
            >
              <option value="microsoft">Microsoft 365 / Azure Entra</option>
              <option value="google">Google Workspace</option>
              <option value="apple">Apple ID</option>
              <option value="github">GitHub Enterprise</option>
              <option value="okta">Okta SSO</option>
            </select>
          </div>
        </div>

        <div className="mt-3 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <label className="text-[11px] font-mono text-slate-400 uppercase shrink-0">MFA Protocol:</label>
            <select
              value={authProtocol}
              onChange={e => setAuthProtocol(e.target.value)}
              className="rounded-xl bg-slate-950/80 border border-slate-800 px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500 transition-colors"
            >
              <option value="WEBAUTHN_FIDO2">FIDO2 WebAuthn / Passkeys (Hardware Token)</option>
              <option value="TOTP_APP">Time-Based OTP App (Google / MS Authenticator)</option>
              <option value="PUSH_NOTIFICATION">Push Notification (Fatigue Vulnerable)</option>
              <option value="SMS_OTP">Legacy SMS OTP (Vulnerable)</option>
              <option value="PASSWORD_ONLY">Password Only (Zero Protection)</option>
            </select>
          </div>

          <button
            onClick={() => handleEvaluate()}
            disabled={loading}
            className="flex items-center justify-center space-x-2 px-6 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-lg shadow-emerald-600/30 transition-all disabled:opacity-50"
          >
            <Activity className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Evaluating...' : 'Simulate Origin Binding'}</span>
          </button>
        </div>

        {/* Quick Presets */}
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-500 font-mono text-[11px] uppercase mr-1">Presets:</span>
          <button
            onClick={() => loadPreset('https://login.microsoft.com-evilginx-proxy.net/auth', 'microsoft', 'WEBAUTHN_FIDO2')}
            className="px-2.5 py-1 rounded-lg bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/50 transition-colors"
          >
            AiTM Evilginx2 on Microsoft (Passkey Immune)
          </button>
          <button
            onClick={() => loadPreset('https://accounts.google.com/signin/v2/identifier', 'google', 'WEBAUTHN_FIDO2')}
            className="px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
          >
            Authentic Google Workspace (Clean Match)
          </button>
          <button
            onClick={() => loadPreset('https://secure-chase-update.info/login', 'microsoft', 'SMS_OTP')}
            className="px-2.5 py-1 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/50 transition-colors"
          >
            Vulnerable Banking Portal (Legacy SMS 95% Risk)
          </button>
        </div>
      </div>

      {/* Error View */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs">
          {error}
        </div>
      )}

      {/* Assessment Output View */}
      {assessment && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2">
          {/* Top Score & Status Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Card 1: Passkey Cryptographic Immunity */}
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 space-y-2">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Passkey Defense Immunity</div>
              <div className="pt-1">
                {assessment.passkeyImmunityConfirmed ? (
                  <span className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    <ShieldCheck className="w-4 h-4" />
                    <span>IMMUNITY CONFIRMED</span>
                  </span>
                ) : (
                  <span className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-slate-800 text-slate-300 border border-slate-700">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>LEGITIMATE PORTAL</span>
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-400">
                {assessment.passkeyImmunityConfirmed
                  ? 'FIDO2 authenticator refuses to sign proxy origin'
                  : 'Official relying party matches origin'}
              </div>
            </div>

            {/* Card 2: MitM Proxy Vulnerability */}
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 space-y-2">
              <div className="text-[11px] font-mono text-slate-400 uppercase">AiTM Proxy Vulnerability</div>
              <div className="flex items-baseline space-x-2">
                <span
                  className={`text-4xl font-black font-mono ${
                    assessment.mitmProxyVulnerabilityScore === 0
                      ? 'text-emerald-400'
                      : assessment.mitmProxyVulnerabilityScore <= 50
                      ? 'text-amber-400'
                      : 'text-rose-400'
                  }`}
                >
                  {assessment.mitmProxyVulnerabilityScore}%
                </span>
              </div>
              <div className="text-xs text-slate-400">
                {assessment.mitmProxyVulnerabilityScore === 0
                  ? 'Zero risk of cookie theft'
                  : 'Session cookie vulnerable to capture'}
              </div>
            </div>

            {/* Card 3: Origin Binding Mismatch */}
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 space-y-2">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Origin vs rpId Match</div>
              <div className="pt-1">
                {assessment.originBindingMismatch ? (
                  <span className="flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>ORIGIN MISMATCH</span>
                  </span>
                ) : (
                  <span className="flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>ORIGIN VERIFIED</span>
                  </span>
                )}
              </div>
              <div className="text-xs font-mono text-slate-400 truncate pt-1">
                rpId: {assessment.relyingPartyId}
              </div>
            </div>

            {/* Card 4: MFA Strength Tier */}
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 space-y-2">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Assessed Auth Tier</div>
              <div className="text-sm font-bold text-white pt-1">
                {assessment.mfaStrengthTier.replace(/_/g, ' ')}
              </div>
              <div className="text-xs text-slate-400">
                {assessment.mfaStrengthTier === 'PHISHING_RESISTANT_FIDO2'
                  ? 'CISA / NIST SP 800-63B Compliant'
                  : 'Below NIST Phishing-Resistant Tier'}
              </div>
            </div>
          </div>

          {/* Detailed Origin Binding Analysis Panel */}
          <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-6 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center space-x-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              <span>WebAuthn Cryptographic Handshake Deconstruction</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="text-[10px] text-slate-400 uppercase">Client Browser Effective Origin</div>
                <div className="text-white font-bold break-all">{assessment.effectiveOrigin}</div>
                <p className="text-[11px] text-slate-500 font-sans">
                  The client browser injects this exact origin string into the cryptographic clientDataJSON hash.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="text-[10px] text-slate-400 uppercase">Legitimate Brand Relying Party (rpId)</div>
                <div className="text-emerald-400 font-bold break-all">{assessment.relyingPartyId}</div>
                <p className="text-[11px] text-slate-500 font-sans">
                  The official authentic identity provider backend verifies that the signed origin strictly matches this domain.
                </p>
              </div>
            </div>
          </div>

          {/* Recommended Security Actions */}
          <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-6 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center space-x-2">
              <Shield className="w-4 h-4 text-indigo-400" />
              <span>Recommended Zero-Trust Defense Actions</span>
            </h3>
            <div className="space-y-2">
              {assessment.recommendedSecurityActions.map((action, i) => (
                <div
                  key={i}
                  className="flex items-start space-x-2.5 p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs text-slate-300"
                >
                  <ArrowRight className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{action}</span>
                </div>
              ))}
            </div>
          </div>

          {/* WebAuthn Policy Enforcer Snippet */}
          <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-6 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Enterprise FIDO2 Policy Enforcer JSON Configuration</span>
              </h3>
              <button
                onClick={handleCopySnippet}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-colors"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>{copiedSnippet ? 'Copied!' : 'Copy Policy'}</span>
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 text-emerald-300 font-mono text-xs overflow-x-auto">
              {assessment.webauthnPolicyEnforcementSnippet}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
export default FIDO2GuardPage;
