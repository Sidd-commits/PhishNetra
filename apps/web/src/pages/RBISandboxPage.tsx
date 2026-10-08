import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
  RBISession,
  RBISecurityPolicy,
  RBIBrowserEvent
} from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Activity,
  Globe,
  Lock,
  RefreshCw,
  Power,
  Play,
  CheckCircle2,
  AlertTriangle,
  Code,
  Eye,
  Sliders,
  Cpu,
  Download,
  Key,
  Flame,
  Check,
  Zap,
  Radio,
  ExternalLink
} from 'lucide-react';

export const RBISandboxPage: React.FC = () => {
  const { showToast } = useToast();

  const [sessions, setSessions] = useState<RBISession[]>([]);
  const [activeSession, setActiveSession] = useState<RBISession | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [launching, setLaunching] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'STREAM' | 'EVENTS' | 'DOM' | 'FORENSICS'>('STREAM');

  // Session Launcher Form State
  const [targetUrl, setTargetUrl] = useState<string>('https://secure-login-portal-verify.support-desk.tk');
  const [securityPolicy, setSecurityPolicy] = useState<RBISecurityPolicy>({
    blockWebSockets: true,
    blockWebRTC: true,
    blockClipboardWrite: true,
    blockFormSubmit: true,
    canvasRandomization: true,
    stripMaliciousScripts: true,
    enforceZeroTrustCSP: true
  });
  const [showPolicyConfig, setShowPolicyConfig] = useState<boolean>(false);

  useEffect(() => {
    loadSessions();
  }, []);

  const loadSessions = async () => {
    setLoading(true);
    try {
      const data = await api.listRBISessions();
      setSessions(data);
      if (data.length > 0 && !activeSession) {
        setActiveSession(data[0]);
      }
    } catch (err: any) {
      showToast('error', 'Load Failed', err.response?.data?.error || 'Failed to load RBI sessions');
    } finally {
      setLoading(false);
    }
  };

  const handleLaunchSession = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) {
      showToast('warning', 'URL Required', 'Please enter a target URL to isolate');
      return;
    }

    setLaunching(true);
    try {
      const session = await api.createRBISession({
        targetUrl: targetUrl.trim(),
        securityPolicy
      });
      setSessions(prev => [session, ...prev]);
      setActiveSession(session);
      showToast('success', 'RBI Sandbox Provisioned', `Container ${session.containerId} running with Zero-Trust air-gap isolation`);
    } catch (err: any) {
      showToast('error', 'Provisioning Error', err.response?.data?.error || 'Failed to launch RBI sandbox session');
    } finally {
      setLaunching(false);
    }
  };

  const handleTerminateSession = async (id: string) => {
    try {
      const updated = await api.terminateRBISession(id);
      setSessions(prev => prev.map(s => (s.id === updated.id ? updated : s)));
      if (activeSession?.id === updated.id) {
        setActiveSession(updated);
      }
      showToast('info', 'Sandbox Terminated', `Container ${updated.containerId} purged from memory`);
    } catch (err: any) {
      showToast('error', 'Termination Failed', err.response?.data?.error || 'Could not terminate session');
    }
  };

  const handleExportForensics = () => {
    if (!activeSession) return;
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(activeSession, null, 2))}`;
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', jsonString);
    downloadAnchor.setAttribute('download', `rbi_forensics_${activeSession.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showToast('success', 'Export Complete', 'RBI session forensic artifact downloaded');
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
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-indigo-500/20 via-purple-500/20 to-pink-500/20 border border-indigo-500/30 text-indigo-400 shadow-lg shadow-indigo-500/10">
              <ShieldCheck className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-indigo-400 via-purple-300 to-pink-400 bg-clip-text text-transparent">
                  Zero-Trust Remote Browser Isolation (RBI) Sandbox
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  Ephemeral Air-Gap
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-1">
                Render untrusted phishing pages in disposable server-side sandboxes with dynamic DOM de-weaponization and live threat telemetry.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadSessions}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 hover:text-white hover:bg-slate-800 transition text-sm font-medium shadow-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowPolicyConfig(!showPolicyConfig)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-indigo-950/60 border border-indigo-500/40 text-indigo-300 hover:bg-indigo-900/60 transition text-sm font-medium shadow-sm"
          >
            <Sliders className="w-4 h-4" />
            Security Policies
          </button>
        </div>
      </div>

      {/* Policy Customization Drawer (Collapsible) */}
      {showPolicyConfig && (
        <div className="p-5 rounded-xl bg-slate-900/90 border border-indigo-500/30 backdrop-blur-md space-y-4 shadow-xl">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-indigo-300 flex items-center gap-2">
              <Shield className="w-4 h-4 text-indigo-400" />
              Air-Gapped Zero-Trust Browser Sandbox Policies
            </h3>
            <span className="text-xs text-slate-400">Applies immediately to new container instances</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <label className="flex items-start gap-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={securityPolicy.stripMaliciousScripts}
                onChange={e => setSecurityPolicy(prev => ({ ...prev, stripMaliciousScripts: e.target.checked }))}
                className="mt-1 rounded bg-slate-900 border-slate-700 text-indigo-500 focus:ring-indigo-500"
              />
              <div className="text-xs">
                <div className="font-semibold text-slate-200">Disarm Dynamic Scripts</div>
                <div className="text-slate-400 mt-0.5">Neutralize eval, Function constructors, and script tags</div>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={securityPolicy.blockFormSubmit}
                onChange={e => setSecurityPolicy(prev => ({ ...prev, blockFormSubmit: e.target.checked }))}
                className="mt-1 rounded bg-slate-900 border-slate-700 text-indigo-500 focus:ring-indigo-500"
              />
              <div className="text-xs">
                <div className="font-semibold text-slate-200">Trap Form Harvests</div>
                <div className="text-slate-400 mt-0.5">Prevent POST exfiltration to adversary endpoints</div>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={securityPolicy.blockClipboardWrite}
                onChange={e => setSecurityPolicy(prev => ({ ...prev, blockClipboardWrite: e.target.checked }))}
                className="mt-1 rounded bg-slate-900 border-slate-700 text-indigo-500 focus:ring-indigo-500"
              />
              <div className="text-xs">
                <div className="font-semibold text-slate-200">Intercept Keyloggers</div>
                <div className="text-slate-400 mt-0.5">Disarm keydown sniffers & clipboard hijacking</div>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={securityPolicy.canvasRandomization}
                onChange={e => setSecurityPolicy(prev => ({ ...prev, canvasRandomization: e.target.checked }))}
                className="mt-1 rounded bg-slate-900 border-slate-700 text-indigo-500 focus:ring-indigo-500"
              />
              <div className="text-xs">
                <div className="font-semibold text-slate-200">Canvas Fingerprint Cloak</div>
                <div className="text-slate-400 mt-0.5">Add noise to HTML5 Canvas and WebGL probes</div>
              </div>
            </label>
          </div>
        </div>
      )}

      {/* URL Launcher Bar */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-xl">
        <form onSubmit={handleLaunchSession} className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <Globe className="w-5 h-5 text-indigo-400" />
            </div>
            <input
              type="text"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              placeholder="https://malicious-domain.com/login"
              className="w-full pl-11 pr-4 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-sm font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={launching}
            className="flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-600 hover:from-indigo-500 hover:to-purple-500 text-white font-medium text-sm transition shadow-lg shadow-indigo-500/20 disabled:opacity-50"
          >
            {launching ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Spawning Container...
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                Launch Air-Gapped Session
              </>
            )}
          </button>
        </form>
      </div>

      {/* Main Sandbox Grid: Left Viewport (70%), Right Live Stream & Policies (30%) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Browser Chrome + Render Viewport */}
        <div className="lg:col-span-2 space-y-4">
          <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-2xl flex flex-col min-h-[580px]">
            {/* Browser Top Navigation Bar */}
            <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block"></span>
                <span className="w-3 h-3 rounded-full bg-yellow-500/80 inline-block"></span>
                <span className="w-3 h-3 rounded-full bg-green-500/80 inline-block"></span>
                <span className="ml-2 text-xs font-mono text-slate-400">
                  {activeSession?.containerId ? `sandbox-${activeSession.containerId}` : 'container-idle'}
                </span>
              </div>

              {/* URL Address Pill */}
              <div className="flex-1 max-w-xl flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 truncate">
                <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span className="text-emerald-400 select-none">isolated://</span>
                <span className="truncate">{activeSession?.targetUrl || targetUrl}</span>
              </div>

              {/* Controls */}
              <div className="flex items-center gap-2">
                {activeSession && activeSession.status === 'RUNNING' && (
                  <button
                    onClick={() => handleTerminateSession(activeSession.id)}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-xs font-medium transition"
                  >
                    <Power className="w-3.5 h-3.5" />
                    Purge
                  </button>
                )}
                <button
                  onClick={handleExportForensics}
                  disabled={!activeSession}
                  className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition text-xs"
                  title="Export Forensics JSON"
                >
                  <Download className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Sandbox Render Area */}
            <div className="flex-1 p-4 bg-slate-950/60 overflow-y-auto relative flex flex-col">
              {activeSession ? (
                <div className="space-y-4 flex-1 flex flex-col">
                  {/* Status Banner */}
                  <div className="flex items-center justify-between p-3 rounded-lg bg-indigo-950/40 border border-indigo-500/30 text-xs">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-indigo-400" />
                      <span className="text-indigo-200 font-semibold">Active Isolation Guard:</span>
                      <span className="text-slate-300">All scripts stripped, keystrokes sanitized, form exfiltration diverted.</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        STATUS: {activeSession.status}
                      </span>
                    </div>
                  </div>

                  {/* Sanitized HTML Sandbox Frame */}
                  <div className="flex-1 min-h-[380px] p-6 rounded-lg bg-slate-900 border border-slate-800 font-sans text-slate-200 relative overflow-hidden flex flex-col justify-between">
                    <div className="space-y-4">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                        <div className="font-semibold text-base text-slate-100 flex items-center gap-2">
                          <Eye className="w-4 h-4 text-purple-400" />
                          {activeSession.activeTabTitle || 'Isolated Page View'}
                        </div>
                        <span className="text-xs font-mono text-slate-500">{activeSession.domain}</span>
                      </div>

                      {/* De-Weaponized Content Render */}
                      <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 text-sm space-y-3">
                        <div className="flex items-center gap-2 text-amber-400 text-xs font-semibold">
                          <AlertTriangle className="w-4 h-4" />
                          <span>DE-WEAPONIZED DOM PAYLOAD:</span>
                        </div>
                        <div
                          className="prose prose-invert max-w-none text-xs text-slate-300"
                          dangerouslySetInnerHTML={{ __html: activeSession.deWeaponizedHtml }}
                        />
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
                      <span>Resolution: {activeSession.sandboxResolution}</span>
                      <span>Ephemeral Container Sandbox</span>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-slate-500">
                  <Shield className="w-12 h-12 text-slate-600 mb-3" />
                  <p className="font-semibold text-slate-400">No Active Isolation Sandbox</p>
                  <p className="text-xs max-w-md mt-1">
                    Enter a suspect URL above and click "Launch Air-Gapped Session" to spin up an isolated zero-trust sandbox container.
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Bottom Tabs: Live Intercept Events / DOM Tree / Forensics */}
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-4 shadow-xl">
            <div className="flex items-center gap-3 border-b border-slate-800 pb-3 mb-4">
              <button
                onClick={() => setActiveTab('STREAM')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  activeTab === 'STREAM'
                    ? 'bg-indigo-600 text-white shadow'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                <Activity className="w-3.5 h-3.5" />
                Live Threat Stream ({activeSession?.liveEvents.length || 0})
              </button>

              <button
                onClick={() => setActiveTab('DOM')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  activeTab === 'DOM'
                    ? 'bg-indigo-600 text-white shadow'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                <Code className="w-3.5 h-3.5" />
                De-Weaponized DOM
              </button>

              <button
                onClick={() => setActiveTab('FORENSICS')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  activeTab === 'FORENSICS'
                    ? 'bg-indigo-600 text-white shadow'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                Session Forensics
              </button>
            </div>

            {/* Tab 1: Live Threat Stream */}
            {activeTab === 'STREAM' && (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {activeSession && activeSession.liveEvents.length > 0 ? (
                  activeSession.liveEvents.map(evt => (
                    <div
                      key={evt.id}
                      className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 flex items-start justify-between gap-3 text-xs"
                    >
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-indigo-400">{evt.eventType}</span>
                          {getSeverityBadge(evt.severity)}
                          <span className="text-slate-500 text-[11px]">{new Date(evt.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <p className="text-slate-300">{evt.details}</p>
                        {evt.sourceSnippet && (
                          <pre className="p-1.5 rounded bg-slate-900 text-slate-400 font-mono text-[11px] overflow-x-auto border border-slate-800">
                            {evt.sourceSnippet}
                          </pre>
                        )}
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 py-4 text-center">No threat events recorded in this session.</p>
                )}
              </div>
            )}

            {/* Tab 2: De-Weaponized DOM */}
            {activeTab === 'DOM' && (
              <div className="p-3 rounded-lg bg-slate-950 font-mono text-xs text-slate-300 max-h-72 overflow-y-auto border border-slate-800">
                <pre>{activeSession?.deWeaponizedHtml || '<!-- No DOM content loaded -->'}</pre>
              </div>
            )}

            {/* Tab 3: Session Forensics */}
            {activeTab === 'FORENSICS' && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                  <div className="font-semibold text-slate-300">Container Sandbox Metadata</div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-500">Container ID:</span>
                    <span className="font-mono text-indigo-300">{activeSession?.containerId || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-500">Domain:</span>
                    <span className="font-mono text-slate-300">{activeSession?.domain || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-500">Started At:</span>
                    <span className="text-slate-300">{activeSession?.startedAt ? new Date(activeSession.startedAt).toLocaleString() : 'N/A'}</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-500">Terminated At:</span>
                    <span className="text-slate-300">{activeSession?.terminatedAt ? new Date(activeSession.terminatedAt).toLocaleString() : 'Active'}</span>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                  <div className="font-semibold text-slate-300">Applied Security Constraints</div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-500">Zero-Trust CSP:</span>
                    <span className="text-emerald-400 font-semibold">{activeSession?.securityPolicy.enforceZeroTrustCSP ? 'ENFORCED' : 'OFF'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-500">Form Trapping:</span>
                    <span className="text-emerald-400 font-semibold">{activeSession?.securityPolicy.blockFormSubmit ? 'ACTIVE' : 'OFF'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-500">Clipboard Lock:</span>
                    <span className="text-emerald-400 font-semibold">{activeSession?.securityPolicy.blockClipboardWrite ? 'ACTIVE' : 'OFF'}</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-500">Canvas Cloaking:</span>
                    <span className="text-emerald-400 font-semibold">{activeSession?.securityPolicy.canvasRandomization ? 'ACTIVE' : 'OFF'}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right 1 Col: Session History & Threat Stats */}
        <div className="space-y-6">
          {/* Quick Stats Widget */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-4">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-indigo-400" />
              RBI Telemetry Overview
            </h3>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                <div className="text-xs text-slate-500">Total Isolated</div>
                <div className="text-xl font-bold text-slate-100 mt-1">{sessions.length}</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                <div className="text-xs text-slate-500">Active Running</div>
                <div className="text-xl font-bold text-emerald-400 mt-1">
                  {sessions.filter(s => s.status === 'RUNNING').length}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                <div className="text-xs text-slate-500">Threats Disarmed</div>
                <div className="text-xl font-bold text-purple-400 mt-1">
                  {sessions.reduce((acc, s) => acc + s.liveEvents.length, 0)}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                <div className="text-xs text-slate-500">Air-Gap Policy</div>
                <div className="text-xl font-bold text-indigo-400 mt-1">100%</div>
              </div>
            </div>
          </div>

          {/* Session History List */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Shield className="w-4 h-4 text-indigo-400" />
                Isolated Sessions ({sessions.length})
              </h3>
            </div>

            <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
              {sessions.map(s => (
                <div
                  key={s.id}
                  onClick={() => setActiveSession(s)}
                  className={`p-3 rounded-lg border transition cursor-pointer text-xs space-y-1.5 ${
                    activeSession?.id === s.id
                      ? 'bg-indigo-950/50 border-indigo-500/50 shadow-md'
                      : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200 truncate max-w-[170px]">{s.domain}</span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        s.status === 'RUNNING'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {s.status}
                    </span>
                  </div>
                  <div className="text-slate-400 font-mono text-[11px] truncate">{s.targetUrl}</div>
                  <div className="flex items-center justify-between text-slate-500 text-[11px] pt-1 border-t border-slate-800/60">
                    <span>Events: {s.liveEvents.length}</span>
                    <span>{new Date(s.startedAt).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))}

              {sessions.length === 0 && !loading && (
                <p className="text-xs text-slate-500 text-center py-6">No previous RBI sessions recorded.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
