import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
  ThreatActorProfile,
  AttributionMatchResult,
  FAIRRiskAssessmentResult
} from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  Users,
  Target,
  DollarSign,
  TrendingUp,
  ShieldAlert,
  ShieldCheck,
  Search,
  RefreshCw,
  Globe,
  Network,
  Cpu,
  Layers,
  Award,
  ChevronRight,
  Flame,
  AlertTriangle,
  BarChart3
} from 'lucide-react';

export const ThreatAttributionPage: React.FC = () => {
  const { showToast } = useToast();
  const [activeTab, setActiveTab] = useState<'attribution' | 'fair'>('attribution');

  // Attribution State
  const [targetDomain, setTargetDomain] = useState('identity-okta-sso-verify.live');
  const [asn, setAsn] = useState('AS13335');
  const [ttpInput, setTtpInput] = useState('T1566.002, T1621, T1583.001');
  const [matching, setMatching] = useState(false);
  const [attributionResult, setAttributionResult] = useState<AttributionMatchResult | null>(null);
  const [threatActors, setThreatActors] = useState<ThreatActorProfile[]>([]);
  const [selectedActor, setSelectedActor] = useState<ThreatActorProfile | null>(null);

  // FAIR Risk Calculator State
  const [annualAttempts, setAnnualAttempts] = useState(5000);
  const [susceptibilityRate, setSusceptibilityRate] = useState(0.12);
  const [controlEffectiveness, setControlEffectiveness] = useState(0.85);
  const [costPerCredential, setCostPerCredential] = useState(4200);
  const [maxRegulatoryFine, setMaxRegulatoryFine] = useState(2500000);
  const [calculatingFair, setCalculatingFair] = useState(false);
  const [fairResult, setFairResult] = useState<FAIRRiskAssessmentResult | null>(null);

  useEffect(() => {
    loadActors();
    calculateFair();
  }, []);

  const loadActors = async () => {
    try {
      const data = await api.listThreatActors();
      setThreatActors(data);
      if (data.length > 0) setSelectedActor(data[0]);
    } catch {
      // Fallback
      setThreatActors([]);
    }
  };

  const handleMatchAttribution = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetDomain.trim()) {
      showToast('warning', 'Missing Domain', 'Enter a target domain to correlate threat actor attribution.');
      return;
    }

    setMatching(true);
    try {
      const ttps = ttpInput.split(',').map(t => t.trim()).filter(Boolean);
      const res = await api.matchThreatActor({
        targetDomain: targetDomain.trim(),
        asn: asn.trim() || undefined,
        ttps: ttps.length > 0 ? ttps : undefined
      });
      setAttributionResult(res);
      showToast('info', 'Attribution Complete', 'Threat actor attribution correlation finished');
    } catch (err: any) {
      showToast('error', 'Attribution Failed', err.message);
    } finally {
      setMatching(false);
    }
  };

  const calculateFair = async () => {
    setCalculatingFair(true);
    try {
      const res = await api.calculateFAIRRisk({
        annualPhishingAttempts: annualAttempts,
        susceptibilityRate,
        controlEffectiveness,
        averageEmployeeCount: 500,
        costPerCompromisedCredential: costPerCredential,
        secondaryRegulatoryFineLikelihood: 0.15,
        maxRegulatoryFine
      });
      setFairResult(res);
    } catch (err: any) {
      showToast('error', 'Calculation Failed', err.message);
    } finally {
      setCalculatingFair(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-indigo-950/70 via-slate-900 to-slate-900 border border-indigo-500/20 p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
                <Target className="w-5 h-5" />
              </div>
              <h1 className="text-xl font-bold text-white tracking-wide">
                Threat Actor Attribution & FAIR Cyber Risk Studio
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 rounded-full font-semibold">
                Milestone 17
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-400 max-w-2xl leading-relaxed">
              Attributes phishing infrastructure and campaign TTPs to known state-sponsored (APT) and cybercrime rings. Quantifies financial loss exposure using the FAIR (Factor Analysis of Information Risk) mathematical framework.
            </p>
          </div>

          <div className="flex items-center space-x-2 bg-slate-950/80 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setActiveTab('attribution')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center space-x-1.5 ${
                activeTab === 'attribution'
                  ? 'bg-indigo-500 text-white shadow-md'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Users className="w-3.5 h-3.5" />
              <span>Actor Attribution</span>
            </button>
            <button
              onClick={() => setActiveTab('fair')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center space-x-1.5 ${
                activeTab === 'fair'
                  ? 'bg-indigo-500 text-white shadow-md'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <DollarSign className="w-3.5 h-3.5" />
              <span>FAIR Risk ($)</span>
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'attribution' ? (
        /* Tab 1: Threat Actor Attribution */
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Attribution Correlation Form & Results */}
          <div className="lg:col-span-2 space-y-6">
            <form onSubmit={handleMatchAttribution} className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
              <h2 className="text-sm font-semibold text-white flex items-center space-x-2">
                <Target className="w-4 h-4 text-indigo-400" />
                <span>Correlate Campaign IOCs to Adversary Profiles</span>
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    Suspect Domain / Target Host
                  </label>
                  <input
                    type="text"
                    value={targetDomain}
                    onChange={(e) => setTargetDomain(e.target.value)}
                    placeholder="e.g. identity-okta-sso-verify.live"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    Autonomous System Number (ASN)
                  </label>
                  <input
                    type="text"
                    value={asn}
                    onChange={(e) => setAsn(e.target.value)}
                    placeholder="e.g. AS13335 (Cloudflare) or AS14061 (DigitalOcean)"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  Observed MITRE ATT&CK TTPs (comma-separated)
                </label>
                <input
                  type="text"
                  value={ttpInput}
                  onChange={(e) => setTtpInput(e.target.value)}
                  placeholder="e.g. T1566.002, T1621, T1583.001"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500 font-mono"
                />
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="submit"
                  disabled={matching}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-500 hover:bg-indigo-400 text-white transition-colors flex items-center space-x-2 shadow-lg shadow-indigo-500/20 disabled:opacity-50"
                >
                  {matching ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Matching Attribution Matrix...</span>
                    </>
                  ) : (
                    <>
                      <Search className="w-3.5 h-3.5" />
                      <span>Correlate Adversary Ring</span>
                    </>
                  )}
                </button>
              </div>
            </form>

            {/* Attribution Outcome */}
            {attributionResult && (
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-5 animate-in fade-in duration-300">
                <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white">Attribution Correlation Verdict</h3>
                    <p className="text-xs text-indigo-300 mt-0.5">{attributionResult.attributionVerdict}</p>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500">{attributionResult.queryId}</span>
                </div>

                {/* Top Matches */}
                <div className="space-y-3">
                  <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">Top Adversary Correlations</span>
                  {attributionResult.topMatches.map((match, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-3"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <span className="text-xs font-bold text-white">{match.actorName}</span>
                          <span className="text-[10px] font-mono text-slate-500 block">Actor ID: {match.actorId}</span>
                        </div>
                        <div className="text-right">
                          <span className="text-xs font-bold font-mono text-indigo-400">
                            {match.attributionConfidence}% Confidence
                          </span>
                        </div>
                      </div>

                      {/* Progress Bar */}
                      <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            match.attributionConfidence >= 75
                              ? 'bg-rose-500'
                              : match.attributionConfidence >= 50
                              ? 'bg-indigo-500'
                              : 'bg-slate-600'
                          }`}
                          style={{ width: `${match.attributionConfidence}%` }}
                        />
                      </div>

                      {/* Diamond Model Breakdown */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] pt-1 border-t border-slate-800/80">
                        <div className="p-2 rounded bg-slate-900/80 border border-slate-800/60">
                          <span className="text-[9px] font-mono text-slate-500 block uppercase">Adversary</span>
                          <span className="text-slate-300 font-semibold">{match.adversaryDiamondModel.adversary}</span>
                        </div>
                        <div className="p-2 rounded bg-slate-900/80 border border-slate-800/60">
                          <span className="text-[9px] font-mono text-slate-500 block uppercase">Capability</span>
                          <span className="text-slate-300">{match.adversaryDiamondModel.capability}</span>
                        </div>
                        <div className="p-2 rounded bg-slate-900/80 border border-slate-800/60">
                          <span className="text-[9px] font-mono text-slate-500 block uppercase">Infrastructure</span>
                          <span className="text-slate-300">{match.adversaryDiamondModel.infrastructure}</span>
                        </div>
                        <div className="p-2 rounded bg-slate-900/80 border border-slate-800/60">
                          <span className="text-[9px] font-mono text-slate-500 block uppercase">Victimology</span>
                          <span className="text-slate-300">{match.adversaryDiamondModel.victimology}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Right Column: Tracked Threat Actor Directory */}
          <div className="space-y-4">
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
              <h3 className="text-xs font-semibold uppercase text-slate-400 tracking-wider flex items-center space-x-2">
                <Users className="w-3.5 h-3.5 text-indigo-400" />
                <span>Tracked APT & Cybercrime Profiles</span>
              </h3>

              <div className="space-y-2">
                {threatActors.map((actor, idx) => (
                  <div
                    key={idx}
                    onClick={() => setSelectedActor(actor)}
                    className={`p-3 rounded-xl border transition-all cursor-pointer ${
                      selectedActor?.actorId === actor.actorId
                        ? 'bg-indigo-500/15 border-indigo-500/40 text-white'
                        : 'bg-slate-950/70 border-slate-800/80 hover:bg-slate-900 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold">{actor.actorName}</span>
                      <span className="text-[10px] font-mono text-slate-400">{actor.originCountry}</span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {actor.mitreAttckTTPs.map((ttp, tIdx) => (
                        <span key={tIdx} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          {ttp}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>

              {selectedActor && (
                <div className="pt-3 border-t border-slate-800 space-y-2 text-xs">
                  <span className="font-semibold text-slate-300 block">Known Attack Signatures:</span>
                  <ul className="space-y-1 text-slate-400 text-[11px]">
                    {selectedActor.knownSignatures.map((sig, sIdx) => (
                      <li key={sIdx} className="flex items-start space-x-1.5">
                        <span className="text-indigo-400 font-bold">•</span>
                        <span>{sig}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        /* Tab 2: FAIR Cyber Risk Quantification */
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: FAIR Parameter Controls */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-5">
            <h2 className="text-sm font-semibold text-white flex items-center space-x-2">
              <DollarSign className="w-4 h-4 text-emerald-400" />
              <span>FAIR Risk Calibration Parameters</span>
            </h2>

            <div className="space-y-4 text-xs">
              <div>
                <div className="flex justify-between text-slate-400 mb-1">
                  <span>Annual Phishing Ingress Attempts</span>
                  <span className="font-mono text-white">{annualAttempts.toLocaleString()}</span>
                </div>
                <input
                  type="range"
                  min="500"
                  max="50000"
                  step="500"
                  value={annualAttempts}
                  onChange={(e) => setAnnualAttempts(Number(e.target.value))}
                  className="w-full accent-indigo-500"
                />
              </div>

              <div>
                <div className="flex justify-between text-slate-400 mb-1">
                  <span>Workforce Susceptibility (Click Rate)</span>
                  <span className="font-mono text-white">{(susceptibilityRate * 100).toFixed(0)}%</span>
                </div>
                <input
                  type="range"
                  min="0.02"
                  max="0.40"
                  step="0.01"
                  value={susceptibilityRate}
                  onChange={(e) => setSusceptibilityRate(Number(e.target.value))}
                  className="w-full accent-indigo-500"
                />
              </div>

              <div>
                <div className="flex justify-between text-slate-400 mb-1">
                  <span>PhishNetra Control Effectiveness</span>
                  <span className="font-mono text-emerald-400 font-bold">{(controlEffectiveness * 100).toFixed(0)}%</span>
                </div>
                <input
                  type="range"
                  min="0.50"
                  max="0.99"
                  step="0.01"
                  value={controlEffectiveness}
                  onChange={(e) => setControlEffectiveness(Number(e.target.value))}
                  className="w-full accent-emerald-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Cost Per Compromised Credential ($)</label>
                <input
                  type="number"
                  value={costPerCredential}
                  onChange={(e) => setCostPerCredential(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Max Regulatory Non-Compliance Fine ($)</label>
                <input
                  type="number"
                  value={maxRegulatoryFine}
                  onChange={(e) => setMaxRegulatoryFine(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                />
              </div>

              <button
                onClick={calculateFair}
                disabled={calculatingFair}
                className="w-full py-2.5 rounded-xl font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition-colors flex items-center justify-center space-x-2 shadow-lg shadow-emerald-500/20"
              >
                {calculatingFair ? <RefreshCw className="w-4 h-4 animate-spin" /> : <BarChart3 className="w-4 h-4" />}
                <span>Recalculate Exposure</span>
              </button>
            </div>
          </div>

          {/* Right Column: Financial Exposure Dashboard */}
          <div className="lg:col-span-2 space-y-6">
            {fairResult && (
              <div className="space-y-6">
                {/* 3 KPI Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-500">Expected Annual Loss (ALE)</span>
                    <div className="text-xl font-bold font-mono text-white">
                      ${fairResult.totalExpectedAnnualLoss.toLocaleString()}
                    </div>
                    <span className="text-[10px] font-mono text-slate-400 block">
                      Tier: <strong className="text-indigo-400">{fairResult.riskTier}</strong>
                    </span>
                  </div>

                  <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-500">Loss Mitigated by PhishNetra</span>
                    <div className="text-xl font-bold font-mono text-emerald-400">
                      ${fairResult.annualLossMitigatedByPhishNetra.toLocaleString()}
                    </div>
                    <span className="text-[10px] font-mono text-emerald-300 block">
                      {(controlEffectiveness * 100).toFixed(0)}% Attack Surface Reduction
                    </span>
                  </div>

                  <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-500">Defense ROI Multiple</span>
                    <div className="text-xl font-bold font-mono text-cyan-400">
                      {fairResult.defenseRoiMultiple}x
                    </div>
                    <span className="text-[10px] font-mono text-slate-400 block">
                      Annual Return on Investment
                    </span>
                  </div>
                </div>

                {/* Probabilistic Distribution Breakdown */}
                <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-4">
                  <h3 className="text-xs font-semibold uppercase text-slate-400 tracking-wider flex items-center space-x-2">
                    <TrendingUp className="w-4 h-4 text-indigo-400" />
                    <span>FAIR Probabilistic Loss Distribution</span>
                  </h3>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                    <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-mono uppercase text-emerald-400">10th Percentile (Optimistic)</span>
                      <div className="text-base font-bold font-mono text-white">
                        ${fairResult.lossDistribution.tenthPercentile.toLocaleString()}
                      </div>
                      <p className="text-[10px] text-slate-400">Low-frequency attacks with rapid SOC remediation</p>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-950/70 border border-indigo-500/30 bg-indigo-500/5 space-y-1">
                      <span className="text-[10px] font-mono uppercase text-indigo-300 font-bold">50th Percentile (Median)</span>
                      <div className="text-base font-bold font-mono text-white">
                        ${fairResult.lossDistribution.fiftiethPercentile.toLocaleString()}
                      </div>
                      <p className="text-[10px] text-slate-400">Expected annual loss across normal operating conditions</p>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-950/70 border border-rose-500/30 space-y-1">
                      <span className="text-[10px] font-mono uppercase text-rose-400">90th Percentile (Worst-Case)</span>
                      <div className="text-base font-bold font-mono text-white">
                        ${fairResult.lossDistribution.ninetiethPercentile.toLocaleString()}
                      </div>
                      <p className="text-[10px] text-slate-400">Severe multi-stage breach involving regulatory scrutiny</p>
                    </div>
                  </div>

                  {/* Summary Breakdown */}
                  <div className="p-3 rounded-xl bg-slate-950/50 border border-slate-800/80 text-xs text-slate-400 space-y-1">
                    <div className="flex justify-between">
                      <span>Loss Event Frequency (LEF):</span>
                      <span className="font-mono text-white">{fairResult.lossEventFrequency} breaches/year</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Primary Response Loss:</span>
                      <span className="font-mono text-white">${fairResult.primaryLossExpected.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Secondary Penalties & Regulatory Fine Exposure:</span>
                      <span className="font-mono text-white">${fairResult.secondaryLossExpected.toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
