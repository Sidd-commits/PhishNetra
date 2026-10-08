import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
  TarpitTask,
  LaunchTarpitTaskRequest,
  PoisonedCredential
} from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  Flame,
  Zap,
  ShieldAlert,
  Server,
  Activity,
  Play,
  Square,
  RefreshCw,
  Clock,
  Key,
  Globe,
  Sliders,
  Database,
  BarChart3,
  AlertTriangle,
  CheckCircle2,
  Download,
  Fingerprint,
  Radio,
  Cpu
} from 'lucide-react';

export const PhishingTarpitPage: React.FC = () => {
  const { showToast } = useToast();

  const [tasks, setTasks] = useState<TarpitTask[]>([]);
  const [activeTask, setActiveTask] = useState<TarpitTask | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [launching, setLaunching] = useState<boolean>(false);

  // Form State
  const [targetUrl, setTargetUrl] = useState<string>('https://phishing-portal-auth.xyz/login.php');
  const [targetFormAction, setTargetFormAction] = useState<string>('https://phishing-portal-auth.xyz/api/post-credentials');
  const [concurrency, setConcurrency] = useState<number>(5);
  const [credentialsCount, setCredentialsCount] = useState<number>(200);
  const [targetBrand, setTargetBrand] = useState<string>('Microsoft 365');

  useEffect(() => {
    loadTasks();
  }, []);

  const loadTasks = async () => {
    setLoading(true);
    try {
      const data = await api.listTarpitTasks();
      setTasks(data);
      if (data.length > 0 && !activeTask) {
        setActiveTask(data[0]);
      }
    } catch (err: any) {
      showToast('error', 'Load Failed', err.response?.data?.error || 'Failed to load Tarpit tasks');
    } finally {
      setLoading(false);
    }
  };

  const handleLaunchTask = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim() || !targetFormAction.trim()) {
      showToast('warning', 'Missing Parameters', 'Target URL and Form Action are required');
      return;
    }

    setLaunching(true);
    try {
      const task = await api.launchTarpitTask({
        targetUrl: targetUrl.trim(),
        targetFormAction: targetFormAction.trim(),
        concurrency,
        credentialsCount,
        targetBrand
      });
      setTasks(prev => [task, ...prev]);
      setActiveTask(task);
      showToast('success', 'Tarpit Flood Launched', `Flooding ${task.targetFormAction} with ${credentialsCount} poisoned honeytokens`);
    } catch (err: any) {
      showToast('error', 'Launch Error', err.response?.data?.error || 'Failed to launch Tarpit task');
    } finally {
      setLaunching(false);
    }
  };

  const handleStopTask = async (id: string) => {
    try {
      const updated = await api.stopTarpitTask(id);
      setTasks(prev => prev.map(t => (t.id === updated.id ? updated : t)));
      if (activeTask?.id === updated.id) {
        setActiveTask(updated);
      }
      showToast('info', 'Tarpit Task Stopped', `Adversary resource exhaustion halted`);
    } catch (err: any) {
      showToast('error', 'Stop Error', err.response?.data?.error || 'Could not stop Tarpit task');
    }
  };

  const handleExportPoisonedCredentials = () => {
    if (!activeTask) return;
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(activeTask.poisonedCredentials, null, 2))}`;
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', jsonString);
    downloadAnchor.setAttribute('download', `tarpit_poisoned_tokens_${activeTask.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showToast('success', 'Export Complete', 'Poisoned honeytoken credentials downloaded');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-amber-500/20 via-orange-500/20 to-red-500/20 border border-amber-500/30 text-amber-400 shadow-lg shadow-amber-500/10">
              <Flame className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-amber-400 via-orange-300 to-red-400 bg-clip-text text-transparent">
                  Phishing Tarpit & Synthetic Credential Poisoner
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-orange-500/20 text-orange-300 border border-orange-500/30">
                  Active Defense
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-1">
                Poison adversary credential harvest databases with millions of realistic synthetic canary honeytokens and exhaust adversary backend infrastructure.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadTasks}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 hover:text-white hover:bg-slate-800 transition text-sm font-medium shadow-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Task Launcher Card */}
      <div className="p-5 rounded-xl bg-slate-900/90 border border-orange-500/30 backdrop-blur-md shadow-xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h2 className="text-sm font-semibold text-orange-300 flex items-center gap-2">
            <Zap className="w-4 h-4 text-orange-400" />
            Configure Synthetic Credential Flooder
          </h2>
          <span className="text-xs text-slate-400">Multi-threaded asynchronous HTTP flood with canary seeds</span>
        </div>

        <form onSubmit={handleLaunchTask} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="space-y-1.5 lg:col-span-2">
            <label className="text-xs font-semibold text-slate-300">Target Phishing Landing Page URL</label>
            <input
              type="text"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              placeholder="https://phishing-portal-auth.xyz/login.php"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500 text-xs font-mono"
            />
          </div>

          <div className="space-y-1.5 lg:col-span-2">
            <label className="text-xs font-semibold text-slate-300">Target Exfiltration Form Action Endpoint</label>
            <input
              type="text"
              value={targetFormAction}
              onChange={e => setTargetFormAction(e.target.value)}
              placeholder="https://phishing-portal-auth.xyz/api/post-credentials"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500 text-xs font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Impersonated Brand Model</label>
            <select
              value={targetBrand}
              onChange={e => setTargetBrand(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:border-orange-500 text-xs"
            >
              <option value="Microsoft 365">Microsoft 365 / Entra ID</option>
              <option value="Google Workspace">Google Workspace</option>
              <option value="Okta SSO">Okta Single Sign-On</option>
              <option value="Chase Banking">Chase Online Banking</option>
              <option value="PayPal">PayPal Security Portal</option>
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Concurrency Threads ({concurrency} workers)</label>
            <input
              type="range"
              min="1"
              max="20"
              value={concurrency}
              onChange={e => setConcurrency(parseInt(e.target.value))}
              className="w-full accent-orange-500 mt-2"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Honeytoken Payload Size ({credentialsCount} items)</label>
            <input
              type="range"
              min="20"
              max="1000"
              step="20"
              value={credentialsCount}
              onChange={e => setCredentialsCount(parseInt(e.target.value))}
              className="w-full accent-orange-500 mt-2"
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={launching}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-orange-600 via-red-600 to-amber-600 hover:from-orange-500 hover:to-red-500 text-white font-medium text-xs transition shadow-lg shadow-orange-500/20 disabled:opacity-50"
            >
              {launching ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Initiating Flooder...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  Launch Honeytoken Flooder
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Main Content Grid: Top Telemetry Metrics Cards */}
      {activeTask && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Honeytokens Injected</span>
              <Database className="w-4 h-4 text-orange-400" />
            </div>
            <div className="text-2xl font-bold text-orange-400">
              {activeTask.totalCredentialsInjected}
            </div>
            <div className="text-[11px] text-slate-500">Synthetic accounts committed to adversary DB</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Adversary Exhaustion</span>
              <Cpu className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">
              {activeTask.targetExhaustionRate}%
            </div>
            <div className="text-[11px] text-slate-500">Adversary server CPU & memory resource drain</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Latency Degradation</span>
              <Activity className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-amber-400">
              {activeTask.meanAdversaryLatencyMs} ms
            </div>
            <div className="text-[11px] text-slate-500">Mean adversary HTTP response delay</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Adversary Status</span>
              <Server className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="text-2xl font-bold text-emerald-400">
              HTTP {activeTask.adversaryStatusCode}
            </div>
            <div className="text-[11px] text-slate-500">Current adversary server HTTP return code</div>
          </div>
        </div>
      )}

      {/* Main Grid: Left Injected Honeytoken Stream, Right Active Tasks List */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Live Honeytoken Stream & Controller */}
        <div className="lg:col-span-2 space-y-4">
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-4 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Fingerprint className="w-4 h-4 text-orange-400" />
                  Synthetic Canary Honeytoken Stream ({activeTask?.poisonedCredentials.length || 0})
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Real-time log of generated and dispatched credentials with embedded tracking tags
                </p>
              </div>

              <div className="flex items-center gap-2">
                {activeTask && activeTask.status === 'ACTIVE' && (
                  <button
                    onClick={() => handleStopTask(activeTask.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-xs font-medium transition"
                  >
                    <Square className="w-3.5 h-3.5" />
                    Halt Tarpit
                  </button>
                )}
                <button
                  onClick={handleExportPoisonedCredentials}
                  disabled={!activeTask || activeTask.poisonedCredentials.length === 0}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export Tokens
                </button>
              </div>
            </div>

            {/* Injected Credentials Table */}
            <div className="overflow-x-auto max-h-[500px]">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider text-[10px] sticky top-0">
                  <tr>
                    <th className="py-2.5 px-3">Synthetic Username</th>
                    <th className="py-2.5 px-3">Decoy Password</th>
                    <th className="py-2.5 px-3">OTP Code</th>
                    <th className="py-2.5 px-3">Canary Tag</th>
                    <th className="py-2.5 px-3">Latency</th>
                    <th className="py-2.5 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {activeTask && activeTask.poisonedCredentials.length > 0 ? (
                    activeTask.poisonedCredentials.map(item => (
                      <tr key={item.id} className="hover:bg-slate-950/40 transition">
                        <td className="py-2 px-3 text-slate-200">{item.username}</td>
                        <td className="py-2 px-3 text-slate-400">••••••••</td>
                        <td className="py-2 px-3 text-amber-400">{item.otpCode}</td>
                        <td className="py-2 px-3 text-indigo-400 text-[10px]">{item.canaryTag}</td>
                        <td className="py-2 px-3 text-slate-400">{item.responseLatencyMs} ms</td>
                        <td className="py-2 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                            {item.submissionStatus}
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="text-center py-8 text-slate-500">
                        No honeytokens injected. Launch a Tarpit task above to begin flooding.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Active Tarpit Tasks List & Strategy Info */}
        <div className="space-y-6">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Server className="w-4 h-4 text-orange-400" />
              Tarpit Tasks ({tasks.length})
            </h3>

            <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1">
              {tasks.map(t => (
                <div
                  key={t.id}
                  onClick={() => setActiveTask(t)}
                  className={`p-3 rounded-lg border transition cursor-pointer text-xs space-y-2 ${
                    activeTask?.id === t.id
                      ? 'bg-orange-950/40 border-orange-500/50 shadow-md'
                      : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200 truncate max-w-[170px]">
                      {t.targetFormAction}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        t.status === 'ACTIVE'
                          ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30 animate-pulse'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {t.status}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400 text-[11px]">
                    <span>Injected: {t.totalCredentialsInjected}</span>
                    <span>Exhaustion: {t.targetExhaustionRate}%</span>
                  </div>

                  <div className="text-slate-500 text-[10px] pt-1 border-t border-slate-800/60">
                    Started: {new Date(t.startedAt).toLocaleTimeString()}
                  </div>
                </div>
              ))}

              {tasks.length === 0 && !loading && (
                <p className="text-xs text-slate-500 text-center py-6">No previous Tarpit tasks recorded.</p>
              )}
            </div>
          </div>

          {/* Defense Rationale Card */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-2 text-xs">
            <h4 className="font-semibold text-slate-200 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-orange-400" />
              Tarpit & Poisoning Mechanics
            </h4>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              By flooding the adversary with 99.9% synthetic credentials carrying cryptographically signed canary markers, any attacker attempting to monetize or log into corporate portals triggers automated canary tripwires.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
