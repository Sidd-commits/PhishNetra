import React, { useState } from 'react';
import {
  Globe,
  Radio,
  Shield,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Server,
  ArrowRight,
  Activity,
  Search,
  Cpu
} from 'lucide-react';
import { api } from '../services/api';
import { BGPIntegrityAssessment } from '@phishnetra/shared';

export const BGPIntegrityPage: React.FC = () => {
  const [target, setTarget] = useState<string>('microsoft.com');
  const [assessment, setAssessment] = useState<BGPIntegrityAssessment | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleProbe = async (domainToProbe?: string) => {
    const finalTarget = domainToProbe || target;
    if (!finalTarget.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const res = await api.probeBGPIntegrity({
        target: finalTarget,
        checkDnssec: true
      });
      setAssessment(res);
    } catch (err: any) {
      setError(err?.response?.data?.message || err.message || 'Failed to execute BGP integrity probe');
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (presetDomain: string) => {
    setTarget(presetDomain);
    handleProbe(presetDomain);
  };

  const getRpkiBadge = (status: 'VALID' | 'INVALID' | 'NOT_FOUND') => {
    switch (status) {
      case 'VALID':
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>RPKI ROA VALID</span>
          </span>
        );
      case 'INVALID':
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>RPKI INVALID (HIJACK)</span>
          </span>
        );
      case 'NOT_FOUND':
      default:
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>RPKI NOT SIGNED</span>
          </span>
        );
    }
  };

  return (
    <div className="min-w-0 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-rose-950/40 to-slate-900 border border-slate-800 p-6 sm:p-8">
        <div className="space-y-2">
          <div className="flex items-center space-x-2.5">
            <span className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
              <Radio className="w-5 h-5 animate-pulse" />
            </span>
            <span className="text-xs font-mono font-semibold tracking-wider text-rose-400 uppercase">
              Milestone 20 • Infrastructure Integrity Radar
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Real-Time BGP Route Hijacking & DNS Cache Poisoning Radar
          </h1>
          <p className="text-sm text-slate-400 max-w-2xl">
            Autonomous multi-resolver consensus analysis, RPKI Route Origin Authorization (ROA) validation,
            and anomalous Autonomous System (AS) path hop inspection for infrastructure-level threat mitigation.
          </p>
        </div>

        {/* Input & Action Bar */}
        <div className="mt-6 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleProbe()}
              placeholder="Enter target domain or IP (e.g. microsoft.com, hijack-simulation.com)"
              className="w-full rounded-xl bg-slate-950/80 border border-slate-800 pl-10 pr-4 py-2.5 text-xs text-white font-mono placeholder-slate-600 focus:outline-none focus:border-rose-500 transition-colors"
            />
          </div>
          <button
            onClick={() => handleProbe()}
            disabled={loading}
            className="flex items-center justify-center space-x-2 px-6 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-lg shadow-rose-600/30 transition-all disabled:opacity-50"
          >
            <Activity className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Probing...' : 'Analyze Infrastructure'}</span>
          </button>
        </div>

        {/* Quick Simulation Presets */}
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-500 font-mono text-[11px] uppercase mr-1">Simulate Attack Scenarios:</span>
          <button
            onClick={() => loadPreset('microsoft.com')}
            className="px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
          >
            Legitimate Microsoft SSO (Clean)
          </button>
          <button
            onClick={() => loadPreset('hijack-simulation-bank.com')}
            className="px-2.5 py-1 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/50 transition-colors"
          >
            BGP Prefix Hijack (Rogue AS)
          </button>
          <button
            onClick={() => loadPreset('poisoned-dns-portal.org')}
            className="px-2.5 py-1 rounded-lg bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 border border-amber-800/50 transition-colors"
          >
            DNS Cache Poisoning (Divergent)
          </button>
        </div>
      </div>

      {/* Error Message */}
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
            {/* Card 1: RRIS Score */}
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 space-y-2">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Route Integrity Score (RRIS)</div>
              <div className="flex items-baseline space-x-2">
                <span
                  className={`text-4xl font-black font-mono ${
                    assessment.routeResolutionIntegrityScore >= 80
                      ? 'text-emerald-400'
                      : assessment.routeResolutionIntegrityScore >= 50
                      ? 'text-amber-400'
                      : 'text-rose-400'
                  }`}
                >
                  {assessment.routeResolutionIntegrityScore}
                </span>
                <span className="text-xs text-slate-500 font-mono">/ 100</span>
              </div>
              <div className="text-xs text-slate-400">
                {assessment.routeResolutionIntegrityScore >= 80
                  ? 'Pristine routing & resolution'
                  : 'Anomalous routing detected'}
              </div>
            </div>

            {/* Card 2: RPKI Status */}
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 space-y-2">
              <div className="text-[11px] font-mono text-slate-400 uppercase">RPKI ROA Validation</div>
              <div className="pt-1">{getRpkiBadge(assessment.rpkiStatus)}</div>
              <div className="text-xs font-mono text-slate-400 pt-1">
                Announced: {assessment.announcedPrefix}
              </div>
            </div>

            {/* Card 3: Origin ASN */}
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 space-y-2">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Origin Autonomous System</div>
              <div className="text-lg font-bold text-white font-mono">
                AS{assessment.originAsn}
              </div>
              <div className="text-xs text-slate-400 truncate">
                {assessment.asOrgName} ({assessment.asCountry})
              </div>
            </div>

            {/* Card 4: DNSSEC Status */}
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 space-y-2">
              <div className="text-[11px] font-mono text-slate-400 uppercase">DNSSEC Consensus</div>
              <div className="pt-1">
                <span
                  className={`px-2.5 py-1 rounded-full text-xs font-bold border ${
                    assessment.dnssecStatus === 'SECURE'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                  }`}
                >
                  {assessment.dnssecStatus}
                </span>
              </div>
              <div className="text-xs text-slate-400 pt-1">
                {assessment.dnsPoisoningDetected ? 'Cache Poisoning Detected' : 'No Poisoning Observed'}
              </div>
            </div>
          </div>

          {/* AS Path Hop Visualizer */}
          <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-6 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center space-x-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>BGP AS Path Hop Traversal</span>
            </h3>
            <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
              {assessment.asPathHops.map((hop, index) => (
                <React.Fragment key={index}>
                  <div className={`px-3 py-2 rounded-xl border ${
                    index === assessment.asPathHops.length - 1 && assessment.isHijackSuspicious
                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-lg shadow-rose-500/20'
                      : 'bg-slate-800/80 text-slate-200 border-slate-700'
                  }`}>
                    <div className="text-[10px] text-slate-400 uppercase">
                      {index === 0 ? 'Transit Origin' : index === assessment.asPathHops.length - 1 ? 'Target Origin AS' : `Peer Hop ${index}`}
                    </div>
                    <div className="font-bold">AS{hop}</div>
                  </div>
                  {index < assessment.asPathHops.length - 1 && (
                    <ArrowRight className="w-4 h-4 text-slate-600 shrink-0" />
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>

          {/* Multi-Resolver DNS Matrix Table */}
          <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                <Globe className="w-4 h-4 text-indigo-400" />
                <span>Multi-Resolver Recursive DNS Consensus Matrix</span>
              </h3>
              <span className="text-xs font-mono text-slate-400">
                Resolved IP: {assessment.resolvedIp}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <tr>
                    <th className="px-4 py-3">Recursive Resolver</th>
                    <th className="px-4 py-3">Resolved IP Answer</th>
                    <th className="px-4 py-3">TTL</th>
                    <th className="px-4 py-3">Latency</th>
                    <th className="px-4 py-3">DNSSEC</th>
                    <th className="px-4 py-3 text-right">Consensus</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {assessment.resolverResponses.map((res, i) => (
                    <tr key={i} className="hover:bg-slate-800/40 transition-colors">
                      <td className="px-4 py-3 text-white font-sans">
                        <div className="font-bold">{res.resolverName}</div>
                        <div className="text-[10px] text-slate-400 font-mono">{res.resolver}</div>
                      </td>
                      <td className="px-4 py-3 font-semibold text-slate-200">
                        {res.resolvedIps.join(', ')}
                      </td>
                      <td className="px-4 py-3 text-slate-300">
                        <span className={res.ttlSeconds < 30 ? 'text-amber-400 font-bold' : ''}>
                          {res.ttlSeconds}s
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-400">{res.latencyMs} ms</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          res.dnssecStatus === 'SECURE'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                            : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                        }`}>
                          {res.dnssecStatus}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        {res.divergentFromConsensus ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                            DIVERGENT
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                            MATCHED
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Forensic Narrative Box */}
          <div className="rounded-2xl bg-slate-950/80 border border-slate-800 p-6 space-y-2">
            <div className="text-[11px] font-mono text-slate-500 uppercase">Forensic Summary & Incident Audit</div>
            <p className="text-xs text-slate-300 leading-relaxed font-mono">
              {assessment.forensicSummary}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
export default BGPIntegrityPage;
