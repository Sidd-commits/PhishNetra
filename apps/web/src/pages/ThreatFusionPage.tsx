import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
  ThreatFusionEntry,
  BayesianDecayConfig,
  ComplianceFramework,
  ComplianceAuditResult
} from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  Activity,
  Layers,
  Clock,
  ShieldCheck,
  CheckCircle2,
  Sliders,
  RefreshCw,
  Search,
  Filter,
  BarChart2,
  Award,
  Download,
  AlertCircle,
  FileCheck,
  Radio,
  Plus
} from 'lucide-react';

export const ThreatFusionPage: React.FC = () => {
  const { showToast } = useToast();

  const [activeTab, setActiveTab] = useState<'FUSION' | 'COMPLIANCE'>('FUSION');
  const [fusedEntries, setFusedEntries] = useState<ThreatFusionEntry[]>([]);
  const [decayConfig, setDecayConfig] = useState<BayesianDecayConfig | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // New IOC Ingestion Form
  const [newIocValue, setNewIocValue] = useState<string>('');
  const [newIocType, setNewIocType] = useState<'DOMAIN' | 'IP' | 'URL' | 'HASH'>('IP');
  const [evaluating, setEvaluating] = useState<boolean>(false);

  // Compliance Audit State
  const [selectedFramework, setSelectedFramework] = useState<ComplianceFramework>('NIST_CSF_2');
  const [auditResult, setAuditResult] = useState<ComplianceAuditResult | null>(null);
  const [auditing, setAuditing] = useState<boolean>(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [entries, cfg] = await Promise.all([
        api.listFusedThreats(),
        api.getBayesianDecayConfig()
      ]);
      setFusedEntries(entries);
      setDecayConfig(cfg);
    } catch (err: any) {
      showToast('error', 'Load Failed', err.response?.data?.error || 'Failed to load fused threat data');
    } finally {
      setLoading(false);
    }
  };

  const handleEvaluateIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIocValue.trim()) {
      showToast('warning', 'IOC Required', 'Please enter an IP, domain, or hash to evaluate');
      return;
    }

    setEvaluating(true);
    try {
      const evaluated = await api.scoreFusedThreat({
        iocValue: newIocValue.trim(),
        iocType: newIocType
      });
      setFusedEntries(prev => [evaluated, ...prev.filter(x => x.id !== evaluated.id)]);
      setNewIocValue('');
      showToast('success', 'IOC Evaluated', `Assigned base score ${evaluated.baseScore} with decayed score ${evaluated.decayedScore}`);
    } catch (err: any) {
      showToast('error', 'Evaluation Error', err.response?.data?.error || 'Failed to evaluate IOC');
    } finally {
      setEvaluating(false);
    }
  };

  const handleRunAudit = async () => {
    setAuditing(true);
    try {
      const result = await api.runComplianceAudit(selectedFramework);
      setAuditResult(result);
      showToast('success', 'Compliance Audit Complete', `Scored ${result.overallCompliancePercent}% on ${selectedFramework}`);
    } catch (err: any) {
      showToast('error', 'Audit Error', err.response?.data?.error || 'Failed to run compliance audit');
    } finally {
      setAuditing(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-indigo-500/20 via-cyan-500/20 to-teal-500/20 border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-500/10">
              <Layers className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-cyan-400 via-indigo-300 to-teal-400 bg-clip-text text-transparent">
                  Threat Intelligence Fusion & Compliance Studio
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  Bayesian Half-Life
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-1">
                Multi-feed IOC consensus engine with exponential half-life temporal decay and automated NIST / CIS / SOC 2 Zero-Trust compliance auditing.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setActiveTab('FUSION')}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition ${
              activeTab === 'FUSION'
                ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-500/20'
                : 'bg-slate-900 border border-slate-700 text-slate-300 hover:text-white'
            }`}
          >
            <Activity className="w-4 h-4" />
            Threat Fusion Matrix
          </button>
          <button
            onClick={() => {
              setActiveTab('COMPLIANCE');
              if (!auditResult) handleRunAudit();
            }}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition ${
              activeTab === 'COMPLIANCE'
                ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-500/20'
                : 'bg-slate-900 border border-slate-700 text-slate-300 hover:text-white'
            }`}
          >
            <Award className="w-4 h-4" />
            Compliance Posture
          </button>
        </div>
      </div>

      {activeTab === 'FUSION' && (
        <div className="space-y-6">
          {/* Top KPI Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-1">
              <div className="text-xs text-slate-400 flex items-center justify-between">
                <span>Fused IOC Indicators</span>
                <Layers className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-2xl font-bold text-slate-100">{fusedEntries.length}</div>
              <div className="text-[11px] text-slate-500">Cross-feed deduplicated intelligence items</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-1">
              <div className="text-xs text-slate-400 flex items-center justify-between">
                <span>Active Threat IOCs</span>
                <AlertCircle className="w-4 h-4 text-rose-400" />
              </div>
              <div className="text-2xl font-bold text-rose-400">
                {fusedEntries.filter(e => e.status === 'ACTIVE').length}
              </div>
              <div className="text-[11px] text-slate-500">Score &gt; 30 with recent activity</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-1">
              <div className="text-xs text-slate-400 flex items-center justify-between">
                <span>Decayed Benign Items</span>
                <Clock className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-2xl font-bold text-amber-400">
                {fusedEntries.filter(e => e.status === 'DECAYED').length}
              </div>
              <div className="text-[11px] text-slate-500">Aged out via exponential half-life decay</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-1">
              <div className="text-xs text-slate-400 flex items-center justify-between">
                <span>Consensus Confidence</span>
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-2xl font-bold text-emerald-400">
                {Math.round(
                  (fusedEntries.reduce((acc, e) => acc + e.confidence, 0) / (fusedEntries.length || 1)) * 100
                )}
                %
              </div>
              <div className="text-[11px] text-slate-500">Multi-feed verification weight</div>
            </div>
          </div>

          {/* IOC Ingestion & Half-Life Simulation Bar */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl">
            <form onSubmit={handleEvaluateIoc} className="flex flex-col sm:flex-row gap-3">
              <div className="sm:w-48">
                <select
                  value={newIocType}
                  onChange={e => setNewIocType(e.target.value as any)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs"
                >
                  <option value="IP">IP Address (24h Half-Life)</option>
                  <option value="DOMAIN">Domain Name (7d Half-Life)</option>
                  <option value="URL">Full URL (48h Half-Life)</option>
                  <option value="HASH">SHA-256 Hash</option>
                </select>
              </div>

              <input
                type="text"
                value={newIocValue}
                onChange={e => setNewIocValue(e.target.value)}
                placeholder="Enter IOC (e.g., 185.220.101.99 or malicious-drop.xyz)"
                className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono"
              />

              <button
                type="submit"
                disabled={evaluating}
                className="flex items-center justify-center gap-2 px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs transition shadow-lg shadow-cyan-500/20 disabled:opacity-50"
              >
                {evaluating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                Evaluate & Decay
              </button>
            </form>
          </div>

          {/* Fused Intelligence Table */}
          <div className="rounded-xl bg-slate-900 border border-slate-800 shadow-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Fused Multi-Source Threat Registry
              </h2>
              <span className="text-xs text-slate-400 font-mono">
                Decay Formula: baseScore · 2^( -Δt / halfLife )
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="py-3 px-4">IOC Value</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Source Feeds</th>
                    <th className="py-3 px-4">Base Score</th>
                    <th className="py-3 px-4">Decayed Score</th>
                    <th className="py-3 px-4">Half-Life</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {fusedEntries.map(entry => (
                    <tr key={entry.id} className="hover:bg-slate-950/40 transition">
                      <td className="py-3 px-4 text-slate-100 font-semibold">{entry.iocValue}</td>
                      <td className="py-3 px-4 text-slate-400">{entry.iocType}</td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {entry.sourceFeeds.map((f, i) => (
                            <span
                              key={i}
                              className="px-1.5 py-0.5 rounded text-[9px] bg-slate-800 text-cyan-300 border border-slate-700"
                            >
                              {f}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-slate-400">{entry.baseScore}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`font-bold ${
                            entry.decayedScore > 60
                              ? 'text-rose-400'
                              : entry.decayedScore > 30
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {entry.decayedScore}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400">{entry.halfLifeHours}h</td>
                      <td className="py-3 px-4 text-slate-300">{Math.round(entry.confidence * 100)}%</td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            entry.status === 'ACTIVE'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {entry.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Compliance Tab */}
      {activeTab === 'COMPLIANCE' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-xl flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div className="space-y-1">
              <h2 className="text-sm font-semibold text-cyan-300 flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-cyan-400" />
                Autonomous Posture & Certification Audit Studio
              </h2>
              <p className="text-xs text-slate-400">
                Execute automated Zero-Trust adherence checks across major regulatory standards
              </p>
            </div>

            <div className="flex items-center gap-3">
              <select
                value={selectedFramework}
                onChange={e => setSelectedFramework(e.target.value as any)}
                className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200"
              >
                <option value="NIST_CSF_2">NIST CSF 2.0 (Zero-Trust)</option>
                <option value="CIS_CONTROLS_V8">CIS Controls v8</option>
                <option value="SOC_2_TYPE_II">SOC 2 Type II Security</option>
                <option value="ISO_27001">ISO 27001 ISMS</option>
              </select>

              <button
                onClick={handleRunAudit}
                disabled={auditing}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs transition shadow-lg shadow-cyan-500/20 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${auditing ? 'animate-spin' : ''}`} />
                Run Posture Check
              </button>
            </div>
          </div>

          {auditResult && (
            <div className="space-y-4">
              {/* Compliance Header Card */}
              <div className="p-6 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 border border-slate-800 shadow-xl flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div className="space-y-2 max-w-xl">
                  <div className="flex items-center gap-2">
                    <span className="text-lg font-bold text-slate-100">{auditResult.framework} Audit Report</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                      CERTIFIED POSTURE
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">{auditResult.executiveSummary}</p>
                </div>

                <div className="flex flex-col sm:items-end">
                  <div className="text-xs text-slate-400">Compliance Grade</div>
                  <div className="text-4xl font-extrabold text-emerald-400">
                    {auditResult.overallCompliancePercent}%
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    {auditResult.passedControls} of {auditResult.totalControls} Controls Passed
                  </div>
                </div>
              </div>

              {/* Controls List */}
              <div className="space-y-3">
                {auditResult.controls.map(ctrl => (
                  <div
                    key={ctrl.controlId}
                    className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-md flex flex-col md:flex-row md:items-center md:justify-between gap-3 text-xs"
                  >
                    <div className="space-y-1 max-w-2xl">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-cyan-400">{ctrl.controlId}</span>
                        <span className="font-semibold text-slate-200">{ctrl.controlName}</span>
                      </div>
                      <p className="text-slate-400">{ctrl.evidenceDescription}</p>
                    </div>

                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <div className="text-xs font-bold text-slate-200">{ctrl.score}%</div>
                        <div className="text-[10px] text-slate-500">Adherence</div>
                      </div>
                      <span className="px-2.5 py-1 rounded text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        {ctrl.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
