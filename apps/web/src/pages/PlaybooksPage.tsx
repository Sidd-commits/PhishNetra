import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import {
  PlaybookDefinition,
  PlaybookExecutionRun,
  PlaybookTriggerType,
  PlaybookActionType
} from '@phishnetra/shared';
import {
  Zap,
  Play,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Layers,
  ShieldAlert,
  Server,
  Terminal,
  Activity,
  Plus,
  RefreshCw,
  Sliders,
  ChevronRight,
  Send,
  FileCode,
  Flame,
  Globe
} from 'lucide-react';

export const PlaybooksPage: React.FC = () => {
  const { showToast } = useToast();
  const [playbooks, setPlaybooks] = useState<PlaybookDefinition[]>([]);
  const [runs, setRuns] = useState<PlaybookExecutionRun[]>([]);
  const [activeTab, setActiveTab] = useState<'playbooks' | 'history'>('playbooks');
  const [loading, setLoading] = useState<boolean>(true);

  // Trigger Modal
  const [selectedPlaybook, setSelectedPlaybook] = useState<PlaybookDefinition | null>(null);
  const [showTriggerModal, setShowTriggerModal] = useState<boolean>(false);
  const [triggerUrl, setTriggerUrl] = useState<string>('');
  const [triggerBrand, setTriggerBrand] = useState<string>('');
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [activeRunResult, setActiveRunResult] = useState<PlaybookExecutionRun | null>(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [pbList, runList] = await Promise.all([
        api.listPlaybooks(),
        api.listPlaybookRuns()
      ]);
      setPlaybooks(pbList);
      setRuns(runList);
    } catch (err: any) {
      showToast('error', 'Failed to load SOAR playbooks', err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleTogglePlaybook = async (id: string, currentEnabled: boolean) => {
    try {
      const updated = await api.updatePlaybook(id, { enabled: !currentEnabled });
      setPlaybooks(prev => prev.map(p => (p.id === id ? updated : p)));
      showToast('success', 'Playbook Updated', `${updated.name} is now ${updated.enabled ? 'ACTIVE' : 'PAUSED'}`);
    } catch (err: any) {
      showToast('error', 'Update Failed', err.message);
    }
  };

  const handleTriggerPlaybook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedPlaybook || !triggerUrl.trim()) return;

    try {
      setIsExecuting(true);
      const result = await api.triggerPlaybook({
        playbookId: selectedPlaybook.id,
        targetUrl: triggerUrl.trim(),
        targetBrand: triggerBrand.trim() || undefined,
        riskScore: 92,
        verdict: 'PHISHING'
      });
      setActiveRunResult(result);
      setRuns(prev => [result, ...prev]);
      showToast('success', 'Playbook Completed', `Workflow executed: ${result.status}`);
      fetchData();
    } catch (err: any) {
      showToast('error', 'Execution Failed', err.message);
    } finally {
      setIsExecuting(false);
    }
  };

  const getActionIcon = (action: PlaybookActionType) => {
    switch (action) {
      case 'BLOCK_DNS_SINKHOLE':
        return <Globe className="w-3.5 h-3.5 text-cyan-400" />;
      case 'DISPATCH_RFC2142_TAKEDOWN':
        return <Send className="w-3.5 h-3.5 text-amber-400" />;
      case 'CREATE_SOC_CASE':
        return <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />;
      case 'NOTIFY_WEBHOOK':
        return <Server className="w-3.5 h-3.5 text-indigo-400" />;
      default:
        return <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-gradient-to-tr from-amber-500 to-rose-600 rounded-xl shadow-lg shadow-amber-500/20">
              <Zap className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Autonomous SOAR Playbooks Engine</h1>
              <p className="text-xs text-slate-400 font-mono">Real-time incident auto-containment, DNS sinkholing, and automated legal dispatch pipelines</p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          {/* Tab Switcher */}
          <div className="flex items-center bg-slate-900 border border-slate-800 rounded-xl p-1">
            <button
              onClick={() => setActiveTab('playbooks')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === 'playbooks'
                  ? 'bg-amber-500 text-slate-950 shadow-md shadow-amber-500/20'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Active Playbooks ({playbooks.length})
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === 'history'
                  ? 'bg-amber-500 text-slate-950 shadow-md shadow-amber-500/20'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Execution Runs ({runs.length})
            </button>
          </div>

          <button
            onClick={() => fetchData()}
            className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Tab 1: Playbooks Grid */}
      {activeTab === 'playbooks' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in">
          {playbooks.map(pb => (
            <div
              key={pb.id}
              className={`rounded-2xl border p-6 flex flex-col justify-between space-y-6 transition-all ${
                pb.enabled
                  ? 'bg-slate-900/70 border-slate-800 hover:border-amber-500/40'
                  : 'bg-slate-900/30 border-slate-800/50 opacity-60'
              }`}
            >
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono font-bold text-amber-400 tracking-wider">
                      {pb.triggerType.replace(/_/g, ' ')}
                    </span>
                    <h3 className="text-sm font-bold text-white leading-snug">{pb.name}</h3>
                  </div>

                  <input
                    type="checkbox"
                    checked={pb.enabled}
                    onChange={() => handleTogglePlaybook(pb.id, pb.enabled)}
                    className="w-4 h-4 accent-amber-500 rounded cursor-pointer mt-1"
                    title={pb.enabled ? 'Pause playbook' : 'Activate playbook'}
                  />
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">{pb.description}</p>

                {/* Steps Timeline Visual */}
                <div className="space-y-2 pt-2 border-t border-slate-800/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase">Automated Pipeline ({pb.steps.length} Steps)</span>
                  <div className="space-y-1.5">
                    {pb.steps.map((s, idx) => (
                      <div
                        key={s.id}
                        className="p-2 rounded-lg bg-slate-950/80 border border-slate-800/60 flex items-center justify-between text-xs text-slate-300"
                      >
                        <div className="flex items-center space-x-2">
                          <span className="text-[10px] font-mono text-slate-500">0{idx + 1}</span>
                          {getActionIcon(s.actionType)}
                          <span className="font-semibold text-white text-[11px] truncate max-w-[180px]">{s.name}</span>
                        </div>
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                          {s.actionType.split('_')[0]}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Card Footer */}
              <div className="flex items-center justify-between pt-4 border-t border-slate-800/60 text-xs">
                <div className="text-[10px] font-mono text-slate-500">
                  {pb.executionCount} runs • {pb.lastExecutedAt ? new Date(pb.lastExecutedAt).toLocaleDateString() : 'Never'}
                </div>

                <button
                  onClick={() => {
                    setSelectedPlaybook(pb);
                    setTriggerUrl('https://phishing-portal.example/auth');
                    setTriggerBrand('Microsoft');
                    setActiveRunResult(null);
                    setShowTriggerModal(true);
                  }}
                  className="px-3.5 py-1.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs shadow-md shadow-amber-500/20 flex items-center space-x-1.5 transition-colors"
                >
                  <Play className="w-3 h-3 fill-current" />
                  <span>Execute Now</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 2: Execution History */}
      {activeTab === 'history' && (
        <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 space-y-4 animate-in fade-in">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span>SOAR Orchestration Audit Runs ({runs.length})</span>
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 font-mono">
                  <th className="py-2.5 px-3">Run ID</th>
                  <th className="py-2.5 px-3">Playbook</th>
                  <th className="py-2.5 px-3">Target Domain</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Steps Completed</th>
                  <th className="py-2.5 px-3">Triggered At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {runs.map(r => (
                  <tr key={r.id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-3 font-mono text-amber-400 font-bold">{r.id}</td>
                    <td className="py-3 px-3 font-semibold text-white">{r.playbookName}</td>
                    <td className="py-3 px-3 font-mono text-slate-300">{r.targetDomain}</td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        r.status === 'SUCCESS'
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                          : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                      }`}>
                        {r.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400">
                      {r.steps.filter(s => s.status === 'COMPLETED').length} / {r.steps.length}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-500">{new Date(r.startedAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal: Manual Trigger & Live Pipeline Runner */}
      {showTriggerModal && selectedPlaybook && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-in fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Zap className="w-5 h-5 text-amber-400" />
                <span>Execute SOAR Playbook: {selectedPlaybook.name}</span>
              </h3>
              <button onClick={() => setShowTriggerModal(false)} className="text-slate-500 hover:text-white">✕</button>
            </div>

            {!activeRunResult ? (
              <form onSubmit={handleTriggerPlaybook} className="space-y-4">
                <div>
                  <label className="block text-xs font-bold text-slate-300 mb-1">Target Malicious URL *</label>
                  <input
                    type="text"
                    required
                    value={triggerUrl}
                    onChange={e => setTriggerUrl(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-300 mb-1">Target Brand</label>
                  <input
                    type="text"
                    value={triggerBrand}
                    onChange={e => setTriggerBrand(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-amber-500"
                  />
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-1.5">
                  <div className="font-bold text-slate-300 uppercase text-[10px] tracking-wider">Automated Actions to Trigger</div>
                  {selectedPlaybook.steps.map((s, idx) => (
                    <div key={s.id} className="text-slate-400 flex items-center gap-2 text-[11px]">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                      <span>{s.name} ({s.actionType})</span>
                    </div>
                  ))}
                </div>

                <div className="flex items-center justify-end space-x-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowTriggerModal(false)}
                    className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isExecuting}
                    className="px-5 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs shadow-lg shadow-amber-500/20 flex items-center space-x-1.5 transition-colors"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>{isExecuting ? 'Orchestrating Actions...' : 'Run Automated Playbook'}</span>
                  </button>
                </div>
              </form>
            ) : (
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between">
                  <div className="flex items-center space-x-2.5">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <div>
                      <h4 className="text-xs font-bold text-white">Playbook Execution Complete</h4>
                      <p className="text-[11px] text-emerald-300 font-mono">Run ID: {activeRunResult.id}</p>
                    </div>
                  </div>
                  <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-emerald-500 text-slate-950">
                    {activeRunResult.status}
                  </span>
                </div>

                {/* Step results */}
                <div className="space-y-2">
                  <div className="text-xs font-bold text-slate-300 uppercase tracking-wider">Executed Pipeline Outputs</div>
                  {activeRunResult.steps.map(s => (
                    <div key={s.id} className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-1">
                      <div className="flex justify-between font-bold text-white">
                        <span>{s.name}</span>
                        <span className="text-emerald-400 font-mono">{s.executionDurationMs}ms</span>
                      </div>
                      <p className="text-[11px] text-slate-400 font-mono">{s.output}</p>
                    </div>
                  ))}
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    onClick={() => setShowTriggerModal(false)}
                    className="px-4 py-2 rounded-xl bg-slate-800 text-xs font-bold text-white hover:bg-slate-700"
                  >
                    Close & View Runs
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
