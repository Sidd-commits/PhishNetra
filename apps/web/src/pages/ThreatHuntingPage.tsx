import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import {
  ThreatHuntQueryType,
  ThreatHuntResult,
  ForensicArtifact
} from '@phishnetra/shared';
import {
  Search,
  Crosshair,
  FileCode,
  ShieldAlert,
  Lock,
  Layers,
  Network,
  Activity,
  ArrowRight,
  Terminal,
  RefreshCw,
  Copy,
  CheckCircle2,
  ExternalLink,
  Shield,
  Clock,
  Sparkles
} from 'lucide-react';

export const ThreatHuntingPage: React.FC = () => {
  const { showToast } = useToast();
  const [queryType, setQueryType] = useState<ThreatHuntQueryType>('DOMAIN_REGEX');
  const [queryValue, setQueryValue] = useState<string>('.*phish.*');
  const [timeRange, setTimeRange] = useState<string>('Last 30 Days');
  const [isSearching, setIsSearching] = useState<boolean>(false);
  const [huntResult, setHuntResult] = useState<ThreatHuntResult | null>(null);

  // Forensic Deep Dive Sandbox
  const [activeForensicUrl, setActiveForensicUrl] = useState<string>('https://secure-login-attempt.example.com');
  const [forensicArtifact, setForensicArtifact] = useState<ForensicArtifact | null>(null);
  const [loadingForensic, setLoadingForensic] = useState<boolean>(false);

  useEffect(() => {
    handleSearch();
    loadForensicArtifact(activeForensicUrl);
  }, []);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!queryValue.trim()) return;

    try {
      setIsSearching(true);
      const res = await api.executeThreatHunt({
        queryType,
        queryValue: queryValue.trim(),
        timeRange
      });
      setHuntResult(res);
      showToast('success', 'Threat Hunt Query Executed', `Found ${res.totalMatches} correlated IOC matches`);
    } catch (err: any) {
      showToast('error', 'Hunt Query Failed', err.message);
    } finally {
      setIsSearching(false);
    }
  };

  const loadForensicArtifact = async (url: string) => {
    try {
      setLoadingForensic(true);
      setActiveForensicUrl(url);
      const art = await api.getForensicArtifact(url);
      setForensicArtifact(art);
    } catch (err: any) {
      showToast('error', 'Failed to load forensic artifact', err.message);
    } finally {
      setLoadingForensic(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    showToast('info', 'Copied to Clipboard', 'Forensic snippet copied.');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-gradient-to-tr from-cyan-500 to-indigo-600 rounded-xl shadow-lg shadow-cyan-500/20">
              <Crosshair className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Advanced Threat Hunting & Forensic Replay Lab</h1>
              <p className="text-xs text-slate-400 font-mono">Multi-vector IOC query engine, deep HAR request inspection, TLS certificate chains & DOM mutation forensics</p>
            </div>
          </div>
        </div>

        <button
          onClick={() => handleSearch()}
          className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 transition-colors self-start md:self-auto"
        >
          <RefreshCw className={`w-4 h-4 ${isSearching ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Query Bar */}
      <form onSubmit={handleSearch} className="bg-slate-900/70 border border-slate-800 rounded-2xl p-4 shadow-xl space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="md:col-span-3">
            <select
              value={queryType}
              onChange={e => setQueryType(e.target.value as ThreatHuntQueryType)}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-400 font-semibold"
            >
              <option value="DOMAIN_REGEX">Domain Pattern (Regex)</option>
              <option value="IP_CIDR">IP Subnet (CIDR)</option>
              <option value="ASN_LOOKUP">Autonomous System (ASN)</option>
              <option value="BRAND_NAME">Targeted Brand Name</option>
              <option value="JA3_FINGERPRINT">JA3 TLS Fingerprint</option>
              <option value="HASH_SHA256">SHA-256 Hash Signature</option>
            </select>
          </div>

          <div className="md:col-span-7 relative">
            <input
              type="text"
              required
              placeholder="Enter search pattern or indicator value..."
              value={queryValue}
              onChange={e => setQueryValue(e.target.value)}
              className="w-full px-3.5 py-2.5 pl-9 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono"
            />
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          </div>

          <div className="md:col-span-2">
            <button
              type="submit"
              disabled={isSearching}
              className="w-full py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 flex items-center justify-center space-x-1.5 transition-colors"
            >
              <Search className="w-3.5 h-3.5" />
              <span>{isSearching ? 'Hunting...' : 'Search IOCs'}</span>
            </button>
          </div>
        </div>
      </form>

      {/* Hunt Results Matrix */}
      {huntResult && (
        <div className="space-y-6 animate-in fade-in">
          {/* Correlated Campaigns & Active Sinkholes Banner */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-2">
              <span className="text-[10px] uppercase font-mono text-slate-500">Correlated Threat Campaigns</span>
              <div className="flex flex-wrap gap-2">
                {huntResult.relatedCampaigns.map(c => (
                  <span key={c} className="px-2.5 py-1 rounded-lg text-xs font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>{c}</span>
                  </span>
                ))}
              </div>
            </div>

            <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-2">
              <span className="text-[10px] uppercase font-mono text-slate-500">Active RPZ DNS Sinkholes</span>
              <div className="flex flex-wrap gap-2">
                {huntResult.activeSinkholes.map(s => (
                  <span key={s} className="px-2.5 py-1 rounded-lg text-xs font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                    {s}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Matches Table */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Discovered Threat Indicators ({huntResult.totalMatches})</span>
              </h3>
              <div className="flex items-center gap-2">
                {huntResult.pivotSuggestions.map((p, idx) => (
                  <button
                    key={idx}
                    onClick={() => {
                      setQueryType('DOMAIN_REGEX');
                      setQueryValue(p.split(' ')[p.split(' ').length - 1] || 'phish');
                    }}
                    className="text-[10px] font-mono px-2 py-1 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/40 transition-colors"
                  >
                    Pivot: {p}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-500 font-mono">
                    <th className="py-2.5 px-3">Indicator</th>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Verdict & Risk</th>
                    <th className="py-2.5 px-3">Origin Layer</th>
                    <th className="py-2.5 px-3">Campaign Tag</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {huntResult.matches.map(m => (
                    <tr key={m.id} className="hover:bg-slate-800/30">
                      <td className="py-3 px-3 font-mono font-bold text-white truncate max-w-xs">{m.indicator}</td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-950 border border-slate-800 text-slate-300">
                          {m.indicatorType}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          m.verdict === 'PHISHING'
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                        }`}>
                          {m.verdict} ({m.riskScore}/100)
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-400 font-mono text-[11px]">{m.sourceLayer}</td>
                      <td className="py-3 px-3 font-mono text-cyan-400">{m.campaignTag || '—'}</td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={() => loadForensicArtifact(m.indicator)}
                          className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-cyan-500/40 text-[11px] font-semibold transition-colors"
                        >
                          Forensic Sandbox
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Forensic Deep Dive Sandbox Viewer */}
      {forensicArtifact && (
        <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 space-y-6 backdrop-blur-sm">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-cyan-400">{forensicArtifact.domain}</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                  HAR Sandbox Replay
                </span>
              </div>
              <h2 className="text-base font-bold text-white mt-1">{forensicArtifact.targetUrl}</h2>
            </div>

            <button
              onClick={() => copyToClipboard(JSON.stringify(forensicArtifact, null, 2))}
              className="px-3 py-1.5 rounded-xl bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-xs flex items-center space-x-1.5 transition-colors self-start md:self-auto"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>Export Raw JSON</span>
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* HAR Request Waterfall */}
            <div className="space-y-3 bg-slate-950/80 p-5 rounded-xl border border-slate-800">
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>HAR Waterfall Requests ({forensicArtifact.harArchive.sampleHttpEntries.length})</span>
              </h4>

              <div className="space-y-2">
                {forensicArtifact.harArchive.sampleHttpEntries.map((entry, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center space-x-2 truncate max-w-xs">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                        {entry.method}
                      </span>
                      <span className="text-white truncate">{entry.url}</span>
                    </div>
                    <div className="flex items-center space-x-2 text-[11px]">
                      <span className="text-emerald-400 font-bold">{entry.status}</span>
                      <span className="text-slate-500">{entry.timeMs}ms</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* TLS Certificate Chain */}
            <div className="space-y-3 bg-slate-950/80 p-5 rounded-xl border border-slate-800">
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Lock className="w-4 h-4 text-amber-400" />
                <span>TLS Certificate Hierarchy ({forensicArtifact.tlsCertificateChain.length} Levels)</span>
              </h4>

              <div className="space-y-2">
                {forensicArtifact.tlsCertificateChain.map((cert, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs space-y-1">
                    <div className="flex justify-between font-bold text-white">
                      <span>{cert.subject}</span>
                      <span className="text-[10px] font-mono text-slate-400">{idx === 0 ? 'Leaf (Host)' : 'Intermediate CA'}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono truncate">Issuer: {cert.issuer}</div>
                    <div className="text-[10px] text-slate-500 font-mono truncate">SHA256: {cert.fingerprintSha256}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* DOM Mutation Forensics */}
          <div className="bg-slate-950/80 p-5 rounded-xl border border-slate-800 space-y-3">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-rose-400" />
              <span>Observed DOM Mutation & Behavioral Injections</span>
            </h4>

            <div className="space-y-1.5 font-mono text-xs text-rose-300">
              {forensicArtifact.domMutations.map((dm, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-500/20">
                  {dm}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
