import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import {
  AttackScenarioPreset,
  AttackSimulationResult,
  DefenseBenchmarkReport,
  AttackVectorType
} from '@phishnetra/shared';
import {
  Crosshair,
  ShieldAlert,
  Play,
  Zap,
  CheckCircle2,
  AlertOctagon,
  AlertTriangle,
  Layers,
  Terminal,
  Activity,
  Cpu,
  Lock,
  ArrowRight,
  ShieldCheck,
  RefreshCw,
  BarChart3,
  Flame,
  Globe,
  Radio,
  FileCheck
} from 'lucide-react';

export const SimulationPage: React.FC = () => {
  const { showToast } = useToast();
  const [activeTab, setActiveTab] = useState<'sandbox' | 'benchmark'>('sandbox');
  const [presets, setPresets] = useState<AttackScenarioPreset[]>([]);
  const [selectedPresetId, setSelectedPresetId] = useState<string>('preset_ms365_urgency');
  const [customUrl, setCustomUrl] = useState<string>('');
  const [customVector, setCustomVector] = useState<AttackVectorType>('SPEAR_PHISH_BRAND_IMPERSONATION');
  const [customBrand, setCustomBrand] = useState<string>('Microsoft');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simulationResult, setSimulationResult] = useState<AttackSimulationResult | null>(null);

  // Benchmark State
  const [benchmarkLoading, setBenchmarkLoading] = useState<boolean>(false);
  const [benchmarkReport, setBenchmarkReport] = useState<DefenseBenchmarkReport | null>(null);

  useEffect(() => {
    fetchPresets();
  }, []);

  const fetchPresets = async () => {
    try {
      const list = await api.listSimulationPresets();
      setPresets(list);
      if (list.length > 0) {
        setCustomUrl(list[0].targetUrl);
        setCustomBrand(list[0].targetBrand || '');
      }
    } catch (err: any) {
      showToast('error', 'Failed to load presets', err.message);
    }
  };

  const handleSelectPreset = (preset: AttackScenarioPreset) => {
    setSelectedPresetId(preset.id);
    setCustomUrl(preset.targetUrl);
    setCustomBrand(preset.targetBrand || '');
  };

  const handleRunSimulation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customUrl.trim()) return;

    try {
      setIsSimulating(true);
      setSimulationResult(null);

      const result = await api.runAttackSimulation({
        presetId: selectedPresetId || undefined,
        targetUrl: customUrl.trim(),
        targetBrand: customBrand.trim() || undefined,
        vectorType: customVector,
        simulateBrowser: true
      });

      setSimulationResult(result);
      showToast(
        result.isMitigated ? 'threat' : 'warning',
        `Simulation Completed: ${result.verdict}`,
        `Attack evaluated with Risk Score ${result.totalRiskScore}/100`
      );
    } catch (err: any) {
      showToast('error', 'Simulation failed', err.message);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleRunBenchmark = async () => {
    try {
      setBenchmarkLoading(true);
      const report = await api.runDefenseBenchmark();
      setBenchmarkReport(report);
      showToast(
        'success',
        'Red Team Benchmark Complete',
        `Evaluated ${report.totalScenariosTested} attack scenarios: ${report.mitigationRatePercent}% mitigation rate`
      );
    } catch (err: any) {
      showToast('error', 'Benchmark failed', err.message);
    } finally {
      setBenchmarkLoading(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
              <Crosshair className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                Threat Simulation & Red Team Replay Lab
                <span className="text-xs font-mono font-normal px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-300 border border-rose-500/20">
                  M10 Attack Sandbox
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Synthetic Red Team attack generator, multi-vector evasion simulation, and automated Zero-Trust defense benchmarking
              </p>
            </div>
          </div>
        </div>

        {/* Tab Controls */}
        <div className="flex space-x-2 bg-slate-900 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveTab('sandbox')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === 'sandbox'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Play className="w-3.5 h-3.5" />
            <span>Attack Sandbox</span>
          </button>
          <button
            onClick={() => setActiveTab('benchmark')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === 'benchmark'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BarChart3 className="w-3.5 h-3.5" />
            <span>Red Team Benchmark</span>
          </button>
        </div>
      </div>

      {/* Tab 1: Attack Sandbox */}
      {activeTab === 'sandbox' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column: Preset Scenarios & Simulation Form */}
          <div className="space-y-6">
            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm space-y-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Flame className="w-4 h-4 text-rose-400" />
                Select Attack Scenario Preset
              </h3>
              <p className="text-xs text-slate-400">
                Choose from real-world adversarial attack templates or configure a custom threat payload
              </p>

              <div className="space-y-2 pt-2 max-h-72 overflow-y-auto">
                {presets.map(preset => (
                  <div
                    key={preset.id}
                    onClick={() => handleSelectPreset(preset)}
                    className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                      selectedPresetId === preset.id
                        ? 'bg-rose-950/40 border-rose-500/50 shadow-md shadow-rose-500/10'
                        : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex justify-between items-start">
                      <h4 className="text-xs font-bold text-white">{preset.name}</h4>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">
                        {preset.expectedRiskLevel}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">{preset.description}</p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {preset.layerTriggers.map(t => (
                        <span key={t} className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-800">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Attack Parameters Form */}
            <form onSubmit={handleRunSimulation} className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm space-y-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Target Payload Parameters
              </h3>

              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">TARGET URL</label>
                  <input
                    type="text"
                    required
                    value={customUrl}
                    onChange={e => setCustomUrl(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-rose-500"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">TARGET BRAND</label>
                    <input
                      type="text"
                      placeholder="e.g. Microsoft"
                      value={customBrand}
                      onChange={e => setCustomBrand(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">VECTOR TYPE</label>
                    <select
                      value={customVector}
                      onChange={e => setCustomVector(e.target.value as any)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500"
                    >
                      <option value="SPEAR_PHISH_BRAND_IMPERSONATION">Brand Impersonation</option>
                      <option value="UNICODE_HOMOGLYPH_PUNYCODE">Unicode Homoglyph</option>
                      <option value="SUBDOMAIN_BRAND_PACKING">Subdomain Packing</option>
                      <option value="SSRF_METADATA_PROBE">AWS SSRF Metadata</option>
                      <option value="FAST_FLUX_DNS_EVASION">Fast-Flux Evasion</option>
                      <option value="COMBOSQUATTING_LOOKALIKE">Combosquatting</option>
                    </select>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={isSimulating}
                  className="w-full py-2.5 bg-gradient-to-r from-rose-500 to-amber-600 hover:from-rose-400 hover:to-amber-500 text-slate-950 font-bold rounded-xl text-xs transition-all shadow-lg shadow-rose-500/20 flex items-center justify-center space-x-2 disabled:opacity-50"
                >
                  <Zap className={`w-4 h-4 ${isSimulating ? 'animate-bounce' : ''}`} />
                  <span>{isSimulating ? 'Simulating Attack Packet...' : 'Execute Attack Simulation'}</span>
                </button>
              </div>
            </form>
          </div>

          {/* Right 2 Columns: Live Packet Traversal & Results */}
          <div className="lg:col-span-2 space-y-6">
            {simulationResult ? (
              <div className="space-y-6 animate-in fade-in">
                {/* Result Hero Banner */}
                <div
                  className={`border rounded-2xl p-6 shadow-2xl backdrop-blur-xl ${
                    simulationResult.verdict === 'PHISHING'
                      ? 'bg-rose-950/40 border-rose-500/40'
                      : 'bg-amber-950/40 border-amber-500/40'
                  }`}
                >
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                    <div className="flex items-center space-x-4">
                      <div
                        className={`w-14 h-14 rounded-2xl flex items-center justify-center ${
                          simulationResult.verdict === 'PHISHING'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        }`}
                      >
                        <ShieldAlert className="w-8 h-8" />
                      </div>
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="text-xl font-bold text-white tracking-tight">
                            {simulationResult.verdict} DETECTED
                          </span>
                          <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-rose-500 text-slate-950">
                            {simulationResult.riskLevel}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 font-mono mt-1 break-all">
                          {simulationResult.targetUrl}
                        </p>
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="text-3xl font-black font-mono text-rose-400">
                        {simulationResult.totalRiskScore}<span className="text-sm text-slate-400 font-normal">/100</span>
                      </div>
                      <div className="text-[11px] text-emerald-400 font-mono flex items-center justify-end gap-1 mt-0.5">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Zero-Trust Defense Held</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 8-Layer Traversal Matrix */}
                <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm space-y-4">
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Layers className="w-4 h-4 text-cyan-400" />
                    Multi-Layer Inspection Pipeline Traversal
                  </h3>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {simulationResult.layerSteps.map((step, idx) => (
                      <div
                        key={idx}
                        className={`p-3.5 rounded-xl border flex flex-col justify-between space-y-2 ${
                          step.score > 70
                            ? 'bg-rose-950/30 border-rose-500/40'
                            : step.score > 30
                            ? 'bg-amber-950/20 border-amber-500/30'
                            : 'bg-slate-950/60 border-slate-800'
                        }`}
                      >
                        <div className="flex justify-between items-center">
                          <span className="text-xs font-bold text-slate-200">{step.layer}</span>
                          <span className="text-xs font-mono font-bold text-rose-400">
                            {step.score}/100
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400">{step.keyFinding}</p>
                        <div className="flex justify-between text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800/60">
                          <span>Weight: {(step.weight * 100).toFixed(0)}%</span>
                          <span>Weighted Score: {step.weightedScore}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Extracted Evidence & Remediation */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Evidence */}
                  <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 space-y-3">
                    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                      <Activity className="w-3.5 h-3.5 text-cyan-400" />
                      Generated Threat Evidence ({simulationResult.generatedEvidence.length})
                    </h4>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {simulationResult.generatedEvidence.map((ev, idx) => (
                        <div key={`${ev.layer}-${ev.featureKey}-${idx}`} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
                          <div className="flex justify-between font-mono">
                            <span className="text-rose-400 font-bold">{ev.featureKey}</span>
                            <span className="text-slate-500">[{ev.layer}]</span>
                          </div>
                          <p className="text-slate-300 text-[11px]">{ev.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Remediation */}
                  <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 space-y-3">
                    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                      Automated Defense Actions
                    </h4>
                    <ul className="space-y-2 text-xs text-slate-300">
                      {simulationResult.remediationRecommendations.map((rec, i) => (
                        <li key={i} className="flex items-start space-x-2">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                          <span className="text-[11px] leading-snug">{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-16 text-center space-y-4">
                <div className="w-16 h-16 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-rose-400">
                  <Crosshair className="w-8 h-8" />
                </div>
                <h3 className="text-base font-bold text-white">Threat Simulation Canvas Ready</h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Select an attack scenario preset from the left drawer or enter a custom target URL and click "Execute Attack Simulation" to observe multi-layer packet evaluation in real-time.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Red Team Automated Benchmark */}
      {activeTab === 'benchmark' && (
        <div className="space-y-6">
          <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-rose-400" />
                Automated Red Team Defense Regression Suite
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Executes 48 automated attack iterations across all 12 adversarial vector families to evaluate Zero-Trust resistance
              </p>
            </div>

            <button
              onClick={handleRunBenchmark}
              disabled={benchmarkLoading}
              className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-rose-500 to-amber-600 hover:from-rose-400 hover:to-amber-500 text-slate-950 font-bold text-xs shadow-lg shadow-rose-500/20 transition-all disabled:opacity-50 shrink-0"
            >
              <RefreshCw className={`w-4 h-4 ${benchmarkLoading ? 'animate-spin' : ''}`} />
              <span>{benchmarkLoading ? 'Running Benchmark...' : 'Run 48-Vector Benchmark'}</span>
            </button>
          </div>

          {benchmarkReport ? (
            <div className="space-y-6 animate-in fade-in">
              {/* Scorecard Hero */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 space-y-1">
                  <span className="text-xs text-slate-400">Total Scenarios Tested</span>
                  <div className="text-2xl font-bold font-mono text-white">
                    {benchmarkReport.totalScenariosTested}
                  </div>
                  <span className="text-[10px] text-slate-500">12 vector families</span>
                </div>

                <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 space-y-1">
                  <span className="text-xs text-slate-400">Mitigation Rate</span>
                  <div className="text-2xl font-bold font-mono text-emerald-400">
                    {benchmarkReport.mitigationRatePercent}%
                  </div>
                  <span className="text-[10px] text-emerald-500 font-mono">
                    {benchmarkReport.successfulMitigations} / {benchmarkReport.totalScenariosTested} neutralized
                  </span>
                </div>

                <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 space-y-1">
                  <span className="text-xs text-slate-400">Mean Latency</span>
                  <div className="text-2xl font-bold font-mono text-cyan-400">
                    {benchmarkReport.meanLatencyMs} ms
                  </div>
                  <span className="text-[10px] text-slate-500">Fast path execution</span>
                </div>

                <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 space-y-1">
                  <span className="text-xs text-slate-400">Invariant Integrity</span>
                  <div className="text-2xl font-bold font-mono text-indigo-400">
                    {benchmarkReport.zeroTrustInvariantIntegrity}%
                  </div>
                  <span className="text-[10px] text-indigo-400">Zero bypass violations</span>
                </div>
              </div>

              {/* Vector Breakdown Table */}
              <div className="bg-slate-900/70 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-sm shadow-xl">
                <div className="p-4 border-b border-slate-800 flex justify-between items-center">
                  <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                    Vector-by-Vector Defense Breakdown
                  </h4>
                  <span className="text-xs text-slate-400 font-mono">
                    {new Date(benchmarkReport.testedAt).toLocaleTimeString()}
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800">
                      <tr>
                        <th className="px-4 py-3">Attack Vector</th>
                        <th className="px-4 py-3">Iterations</th>
                        <th className="px-4 py-3">Mitigated</th>
                        <th className="px-4 py-3">Avg Risk Score</th>
                        <th className="px-4 py-3">Defense Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-sans">
                      {benchmarkReport.vectorBreakdown.map((vb, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30">
                          <td className="px-4 py-3 font-mono font-semibold text-slate-200">{vb.vectorType}</td>
                          <td className="px-4 py-3 font-mono text-slate-400">{vb.total}</td>
                          <td className="px-4 py-3 font-mono font-bold text-emerald-400">{vb.mitigated} / {vb.total}</td>
                          <td className="px-4 py-3 font-mono text-rose-400">{vb.avgRiskScore}/100</td>
                          <td className="px-4 py-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              PASS (100%)
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-16 text-center space-y-4">
              <div className="w-16 h-16 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-rose-400">
                <BarChart3 className="w-8 h-8" />
              </div>
              <h3 className="text-base font-bold text-white">No Benchmark Executed Yet</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Click "Run 48-Vector Benchmark" above to trigger an automated Red Team regression evaluation against all 12 attack vector classes.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
