import React, { useState } from 'react';
import { api } from '../services/api';
import {
  AiTMSessionScanResult,
  AiTMProxyIndicator
} from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Lock,
  Radio,
  Fingerprint,
  RefreshCw,
  Terminal,
  Server,
  Key,
  Globe,
  Sliders,
  AlertTriangle,
  Copy,
  Check,
  Eye,
  FileCode,
  Download
} from 'lucide-react';

export const AiTMDefensePage: React.FC = () => {
  const { showToast } = useToast();

  const [targetUrl, setTargetUrl] = useState<string>('https://login.microsoftonline.com.evil-reverse-proxy.xyz/login');
  const [claimedHost, setClaimedHost] = useState<string>('login.microsoftonline.com');
  const [includeHeaders, setIncludeHeaders] = useState<boolean>(true);
  const [includeCookies, setIncludeCookies] = useState<boolean>(true);
  const [scanning, setScanning] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<AiTMSessionScanResult | null>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) {
      showToast('warning', 'Target Required', 'Please enter a URL to inspect for AiTM reverse proxying');
      return;
    }

    setScanning(true);
    try {
      const result = await api.scanAiTMSession({
        targetUrl: targetUrl.trim(),
        claimedHost: claimedHost.trim() || undefined,
        headers: includeHeaders
          ? {
              'x-forwarded-host': claimedHost.trim() || 'login.microsoftonline.com',
              'x-evilginx-client-ip': '198.51.100.22'
            }
          : undefined,
        cookiesPresent: includeCookies
          ? ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'session_token']
          : undefined
      });

      setScanResult(result);
      if (result.isAiTMProxy) {
        showToast('error', 'AiTM Reverse Proxy Intercepted', `Detected ${result.threatType} with risk score ${result.riskScore}`);
      } else {
        showToast('success', 'Clean Session Verified', 'No AiTM reverse proxy anomalies identified');
      }
    } catch (err: any) {
      showToast('error', 'Inspection Error', err.response?.data?.error || 'Failed to scan for AiTM reverse proxy');
    } finally {
      setScanning(false);
    }
  };

  const handleCopyArtifact = () => {
    if (!scanResult) return;
    navigator.clipboard.writeText(scanResult.mitigationArtifact);
    setCopied(true);
    showToast('info', 'Artifact Copied', 'Mitigation directive copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/40">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-orange-500/20 text-orange-400 border border-orange-500/40">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/40">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/40">LOW</span>;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-rose-500/20 via-red-500/20 to-purple-500/20 border border-rose-500/30 text-rose-400 shadow-lg shadow-rose-500/10">
              <ShieldAlert className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-rose-400 via-red-300 to-purple-400 bg-clip-text text-transparent">
                  Adversary-in-the-Middle (AiTM) Reverse Proxy Defense
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  MFA Session Shield
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-1">
                Intercept Evilginx2, Modlishka, and Muraena reverse proxy relay attacks. Neutralize session hijacking and enforce cryptographic FIDO2/WebAuthn step-up re-authentication.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Inspection Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Scanner Form */}
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-4">
            <h2 className="text-sm font-semibold text-rose-300 flex items-center gap-2">
              <Fingerprint className="w-4 h-4 text-rose-400" />
              AiTM Reverse Proxy Inspector
            </h2>

            <form onSubmit={handleScan} className="space-y-3">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300">Target Suspect Host or URL</label>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={e => setTargetUrl(e.target.value)}
                  placeholder="https://login.microsoftonline.com.evil-proxy.xyz"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 focus:border-rose-500 text-xs font-mono"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300">Target Claimed IdP Domain</label>
                <select
                  value={claimedHost}
                  onChange={e => setClaimedHost(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:border-rose-500 text-xs"
                >
                  <option value="login.microsoftonline.com">Microsoft 365 (login.microsoftonline.com)</option>
                  <option value="accounts.google.com">Google Workspace (accounts.google.com)</option>
                  <option value="auth.okta.com">Okta SSO (auth.okta.com)</option>
                  <option value="github.com">GitHub Enterprise (github.com)</option>
                </select>
              </div>

              <div className="space-y-2 pt-2 border-t border-slate-800/80">
                <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={includeHeaders}
                    onChange={e => setIncludeHeaders(e.target.checked)}
                    className="rounded bg-slate-950 border-slate-700 text-rose-500 focus:ring-rose-500"
                  />
                  <span>Inspect Reverse-Proxy Upstream Headers (`X-Forwarded-Host`)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={includeCookies}
                    onChange={e => setIncludeCookies(e.target.checked)}
                    className="rounded bg-slate-950 border-slate-700 text-rose-500 focus:ring-rose-500"
                  />
                  <span>Probe Session Token Intercept (`ESTSAUTH`, `session_token`)</span>
                </label>
              </div>

              <button
                type="submit"
                disabled={scanning}
                className="w-full mt-2 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-rose-600 via-red-600 to-purple-600 hover:from-rose-500 hover:to-red-500 text-white font-medium text-xs transition shadow-lg shadow-rose-500/20 disabled:opacity-50"
              >
                {scanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Probing Reverse Proxy...
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 fill-current" />
                    Execute AiTM Defense Sweep
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Educational Threat Card */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-2 text-xs">
            <h3 className="font-semibold text-rose-300 flex items-center gap-2">
              <Lock className="w-4 h-4 text-rose-400" />
              How AiTM Defeats Traditional 2FA
            </h3>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Adversary-in-the-Middle reverse proxies act as invisible transparent relays between the victim and legitimate enterprise login portals. By relaying real authentication requests and OTPs in real-time, the proxy intercepts the post-auth session cookies, completely bypassing traditional SMS and TOTP MFA.
            </p>
          </div>
        </div>

        {/* Right 2 Columns: Inspection Result & Defense Artifact */}
        <div className="lg:col-span-2 space-y-6">
          {scanResult ? (
            <div className="space-y-4">
              {/* Top Banner Status */}
              <div
                className={`p-5 rounded-xl border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 shadow-xl ${
                  scanResult.isAiTMProxy
                    ? 'bg-rose-950/40 border-rose-500/50 shadow-rose-500/10'
                    : 'bg-emerald-950/40 border-emerald-500/50 shadow-emerald-500/10'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xl font-bold ${
                        scanResult.isAiTMProxy ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {scanResult.isAiTMProxy ? 'AITM REVERSE PROXY DETECTED' : 'CLEAN AUTHENTICATION SESSION'}
                    </span>
                  </div>
                  <div className="text-xs text-slate-300 font-mono">
                    Target: {scanResult.targetUrl}
                  </div>
                  {scanResult.threatType && (
                    <div className="text-xs font-semibold text-rose-300">
                      Signature Family: {scanResult.threatType}
                    </div>
                  )}
                </div>

                <div className="flex flex-col sm:items-end gap-1">
                  <div className="text-xs text-slate-400">Risk Score</div>
                  <div
                    className={`text-3xl font-extrabold ${
                      scanResult.isAiTMProxy ? 'text-rose-400' : 'text-emerald-400'
                    }`}
                  >
                    {scanResult.riskScore} / 100
                  </div>
                  <span
                    className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                      scanResult.recommendedAction === 'BLOCK_AND_INVALIDATE'
                        ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                        : scanResult.recommendedAction === 'ENFORCE_FIDO2_STEPUP'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    }`}
                  >
                    {scanResult.recommendedAction.replace(/_/g, ' ')}
                  </span>
                </div>
              </div>

              {/* Detected Indicators List */}
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-3">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  Reverse Proxy Indicators ({scanResult.indicators.length})
                </h3>

                <div className="space-y-2">
                  {scanResult.indicators.map((ind, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-rose-400">{ind.type}</span>
                        {getSeverityBadge(ind.severity)}
                      </div>
                      <p className="text-slate-300">{ind.description}</p>
                      <div className="font-mono text-[11px] text-slate-500 bg-slate-900 p-1.5 rounded border border-slate-800">
                        Pattern: {ind.detectedPattern}
                      </div>
                    </div>
                  ))}

                  {scanResult.indicators.length === 0 && (
                    <p className="text-xs text-slate-500 py-3 text-center">
                      No indicators triggered. Target appears to be authentic upstream service.
                    </p>
                  )}
                </div>
              </div>

              {/* Mitigation Directive & NIDS Rules */}
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-purple-400" />
                    Autonomous Mitigation Directive
                  </h3>
                  <button
                    onClick={handleCopyArtifact}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy Directive'}</span>
                  </button>
                </div>

                <pre className="p-3 rounded-lg bg-slate-950 font-mono text-xs text-slate-300 overflow-x-auto border border-slate-800">
                  {scanResult.mitigationArtifact}
                </pre>
              </div>
            </div>
          ) : (
            <div className="h-full min-h-[350px] p-8 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col items-center justify-center text-center text-slate-500">
              <ShieldAlert className="w-12 h-12 text-slate-600 mb-3" />
              <h3 className="text-base font-semibold text-slate-400">Ready for AiTM Sweep</h3>
              <p className="text-xs max-w-md mt-1">
                Enter suspect URL and claimed enterprise identity provider domain on the left to probe for transparent reverse proxies and session hijacking.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
