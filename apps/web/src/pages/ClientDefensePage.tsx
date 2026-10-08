import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
  ClientGuardConfig,
  ClientGuardScriptResult,
  ClientTamperEvent
} from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Code2,
  Copy,
  Check,
  Radio,
  Eye,
  RefreshCw,
  Lock,
  Layers,
  AlertTriangle,
  Zap,
  Globe
} from 'lucide-react';

export const ClientDefensePage: React.FC = () => {
  const { showToast } = useToast();
  const [targetDomain, setTargetDomain] = useState('identity.corporate-sso.internal');
  const [enableDevTools, setEnableDevTools] = useState(true);
  const [enableMutation, setEnableMutation] = useState(true);
  const [enableClickjacking, setEnableClickjacking] = useState(true);
  const [enableWatermark, setEnableWatermark] = useState(true);

  const [generating, setGenerating] = useState(false);
  const [scriptResult, setScriptResult] = useState<ClientGuardScriptResult | null>(null);
  const [tamperEvents, setTamperEvents] = useState<ClientTamperEvent[]>([]);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    loadEvents();
  }, []);

  const loadEvents = async () => {
    try {
      const data = await api.listClientTamperEvents();
      setTamperEvents(data);
    } catch {
      // Fallback
      setTamperEvents([]);
    }
  };

  const handleGenerateScript = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetDomain.trim()) {
      showToast('warning', 'Missing Domain', 'Specify the authoritative target domain.');
      return;
    }

    setGenerating(true);
    try {
      const result = await api.generateClientGuard({
        targetDomain: targetDomain.trim(),
        enableDevToolsTrap: enableDevTools,
        enableMutationTrap: enableMutation,
        enableClickjackingTrap: enableClickjacking,
        enableWatermarking: enableWatermark,
        reportingEndpoint: '/api/client-defense/beacon'
      });
      setScriptResult(result);
      showToast('success', 'Guard Script Generated', `SRI Hash: ${result.scriptIntegrityHash.substring(0, 16)}...`);
    } catch (err: any) {
      showToast('error', 'Generation Failed', err.message);
    } finally {
      setGenerating(false);
    }
  };

  const copyScript = () => {
    if (scriptResult?.obfuscatedScript) {
      navigator.clipboard.writeText(scriptResult.obfuscatedScript);
      setCopied(true);
      showToast('info', 'Copied to Clipboard', 'Client anti-tamper script copied.');
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-cyan-950/70 via-slate-900 to-slate-900 border border-cyan-500/20 p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <h1 className="text-xl font-bold text-white tracking-wide">
                Client-Side Anti-Tampering & DOM Cloaking SDK
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-full font-semibold">
                Milestone 18
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-400 max-w-2xl leading-relaxed">
              Provides client-side runtime application self-protection (RASP) for web login interfaces. Injects real-time DevTools traps, DOM Mutation Observers preventing adversary credential harvesting overlays, and anti-clickjacking frame guards.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => handleGenerateScript()}
              className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors flex items-center space-x-1.5 shadow-lg shadow-cyan-500/20"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Compile Guard Script</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Layout Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Script Configurator */}
        <div className="space-y-6">
          <form onSubmit={handleGenerateScript} className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center space-x-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              <span>Runtime Protection Policy</span>
            </h2>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  Authoritative Domain
                </label>
                <input
                  type="text"
                  value={targetDomain}
                  onChange={(e) => setTargetDomain(e.target.value)}
                  placeholder="e.g. login.corporate-sso.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="space-y-2 pt-2 border-t border-slate-800 text-xs">
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableDevTools}
                    onChange={(e) => setEnableDevTools(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-slate-300">DevTools & Debugger Hook Trap</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableMutation}
                    onChange={(e) => setEnableMutation(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-slate-300">DOM Mutation Overlay Trap</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableClickjacking}
                    onChange={(e) => setEnableClickjacking(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-slate-300">Anti-Clickjacking Framing Guard</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableWatermark}
                    onChange={(e) => setEnableWatermark(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-slate-300">Invisible Anti-Scraping Watermarking</span>
                </label>
              </div>
            </div>

            <button
              type="submit"
              disabled={generating}
              className="w-full py-2.5 rounded-xl font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/20 text-xs disabled:opacity-50"
            >
              {generating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Code2 className="w-3.5 h-3.5" />}
              <span>Generate Obfuscated Guard</span>
            </button>
          </form>

          {/* SRI Hash Card */}
          {scriptResult && (
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 shadow-lg space-y-2 text-xs">
              <span className="text-[10px] font-mono uppercase text-slate-500">Subresource Integrity (SRI) Hash</span>
              <p className="font-mono text-cyan-300 break-all bg-slate-950 p-2 rounded-lg border border-slate-800 text-[11px]">
                {scriptResult.scriptIntegrityHash}
              </p>
            </div>
          )}
        </div>

        {/* Center & Right Column: Script Code & Live Beacon Stream */}
        <div className="lg:col-span-2 space-y-6">
          {/* Script Viewer */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-white flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Client-Side Guard Payload Script</span>
              </span>

              {scriptResult && (
                <button
                  onClick={copyScript}
                  className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors flex items-center space-x-1.5"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? 'Copied' : 'Copy Script'}</span>
                </button>
              )}
            </div>

            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-72">
              {scriptResult ? scriptResult.obfuscatedScript : `// Click 'Compile Guard Script' above to generate client-side tamper guard.`}
            </pre>
          </div>

          {/* Live Tampering Events Telemetry */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase text-slate-400 tracking-wider flex items-center space-x-2">
                <Radio className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
                <span>Client Tampering Beacon Stream</span>
              </h3>
              <span className="text-[10px] font-mono text-slate-500">{tamperEvents.length} Events Logged</span>
            </div>

            <div className="space-y-2.5 max-h-80 overflow-y-auto">
              {tamperEvents.map((evt) => (
                <div
                  key={evt.eventId}
                  className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          evt.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        }`}
                      >
                        {evt.severity}
                      </span>
                      <span className="text-xs font-bold text-white font-mono">{evt.tamperType}</span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="text-[11px] text-slate-400 space-y-0.5 font-mono">
                    <div>Domain: <span className="text-slate-200">{evt.targetDomain}</span> | Client IP: <span className="text-slate-200">{evt.clientIp}</span></div>
                    <div className="text-[10px] text-slate-500 truncate">{evt.userAgent}</div>
                    <pre className="mt-1 p-2 rounded bg-slate-900 border border-slate-800/80 text-[10px] text-slate-300 overflow-x-auto">
                      {JSON.stringify(evt.payloadDetails, null, 2)}
                    </pre>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
