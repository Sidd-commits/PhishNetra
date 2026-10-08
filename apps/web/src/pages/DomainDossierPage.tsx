import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { DomainDossier, TyposquattingMatch } from '@phishnetra/shared';
import {
  Globe,
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Server,
  Calendar,
  Layers,
  ExternalLink,
  Activity,
  Copy,
  Check,
  Hash,
  Clock,
  ArrowRight
} from 'lucide-react';

export const DomainDossierPage: React.FC = () => {
  const { domain: paramDomain } = useParams<{ domain?: string }>();
  const navigate = useNavigate();

  const [inputDomain, setInputDomain] = useState(paramDomain || '');
  const [dossier, setDossier] = useState<DomainDossier | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedVariant, setCopiedVariant] = useState<string | null>(null);

  useEffect(() => {
    if (paramDomain) {
      fetchDossier(paramDomain);
    }
  }, [paramDomain]);

  const fetchDossier = async (target: string) => {
    const clean = target.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    if (!clean) return;

    setLoading(true);
    setError(null);

    try {
      const data = await api.getDomainDossier(clean);
      setDossier(data);
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Failed to retrieve domain dossier.');
      setDossier(null);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputDomain.trim()) return;
    const clean = inputDomain.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    navigate(`/domains/${encodeURIComponent(clean)}`);
    fetchDossier(clean);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedVariant(text);
    setTimeout(() => setCopiedVariant(null), 2000);
  };

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return <span className="px-2.5 py-1 text-xs font-bold rounded-md bg-rose-500/20 text-rose-300 border border-rose-500/40">CRITICAL RISK</span>;
      case 'HIGH':
        return <span className="px-2.5 py-1 text-xs font-bold rounded-md bg-rose-500/20 text-rose-300 border border-rose-500/30">HIGH RISK</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-1 text-xs font-bold rounded-md bg-amber-500/20 text-amber-300 border border-amber-500/30">MEDIUM RISK</span>;
      default:
        return <span className="px-2.5 py-1 text-xs font-bold rounded-md bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">LOW RISK</span>;
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Header & Search */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Domain Intelligence & Dossier Hub</h1>
            <p className="text-sm text-slate-400">
              In-depth domain reputation, RDAP timeline, DNS records, and typosquatting/homoglyph matrix.
            </p>
          </div>
        </div>

        {/* Search Input */}
        <form onSubmit={handleSearch} className="flex items-center space-x-2 max-w-md w-full">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={inputDomain}
              onChange={(e) => setInputDomain(e.target.value)}
              placeholder="e.g. paypal.com or goog1e-security.com"
              className="w-full bg-slate-900/80 border border-slate-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none transition-all"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !inputDomain.trim()}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex items-center space-x-1.5"
          >
            {loading ? <Activity className="w-3.5 h-3.5 animate-spin" /> : <span>Inspect</span>}
          </button>
        </form>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs text-rose-300 flex items-center space-x-3">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {dossier ? (
        <div className="space-y-8">
          {/* Top Dossier Overview Card */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono text-indigo-400">DOMAIN DOSSIER</span>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
                    {dossier.registrableDomain}
                  </span>
                </div>
                <div className="text-2xl font-bold text-white font-mono mt-1">
                  {dossier.domain}
                </div>
              </div>

              <div className="flex items-center space-x-4">
                <div className="text-right">
                  <div className="text-[10px] text-slate-400 uppercase font-semibold">Composite Domain Risk</div>
                  <div className="text-xl font-bold font-mono text-white mt-0.5">{dossier.riskScore} / 100</div>
                </div>
                {getRiskBadge(dossier.riskLevel)}
              </div>
            </div>

            {/* Quick Metrics Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-slate-950/70 p-4 rounded-lg border border-slate-800/80">
                <div className="flex items-center space-x-2 text-slate-400 text-xs font-semibold uppercase">
                  <Calendar className="w-4 h-4 text-indigo-400" />
                  <span>Domain Age</span>
                </div>
                <div className="text-sm font-semibold text-white font-mono mt-2">
                  {dossier.domainAgeDays !== null && dossier.domainAgeDays !== undefined
                    ? `${dossier.domainAgeDays} days (${dossier.ageCategory})`
                    : 'Unknown / Hidden'}
                </div>
              </div>

              <div className="bg-slate-950/70 p-4 rounded-lg border border-slate-800/80">
                <div className="flex items-center space-x-2 text-slate-400 text-xs font-semibold uppercase">
                  <Server className="w-4 h-4 text-cyan-400" />
                  <span>Registrar</span>
                </div>
                <div className="text-sm font-semibold text-white truncate font-mono mt-2" title={dossier.registrar || 'N/A'}>
                  {dossier.registrar || 'Private / Unlisted'}
                </div>
              </div>

              <div className="bg-slate-950/70 p-4 rounded-lg border border-slate-800/80">
                <div className="flex items-center space-x-2 text-slate-400 text-xs font-semibold uppercase">
                  <Layers className="w-4 h-4 text-emerald-400" />
                  <span>Total Scans Logged</span>
                </div>
                <div className="text-sm font-semibold text-white font-mono mt-2">
                  {dossier.totalScans} scans ({dossier.phishingScans} phishing)
                </div>
              </div>

              <div className="bg-slate-950/70 p-4 rounded-lg border border-slate-800/80">
                <div className="flex items-center space-x-2 text-slate-400 text-xs font-semibold uppercase">
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                  <span>Community Reports</span>
                </div>
                <div className="text-sm font-semibold text-white font-mono mt-2">
                  {dossier.communityReportsCount} reported incidents
                </div>
              </div>
            </div>

            {/* DNS Nameservers & Resolved IPs */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <div className="bg-slate-950/50 p-4 rounded-lg border border-slate-800 text-xs space-y-2">
                <span className="text-slate-400 font-semibold uppercase text-[10px] tracking-wider">
                  Active Nameservers ({dossier.nameservers.length})
                </span>
                <div className="font-mono text-slate-300 space-y-1">
                  {dossier.nameservers.length > 0 ? (
                    dossier.nameservers.map((ns, idx) => <div key={idx} className="truncate">• {ns}</div>)
                  ) : (
                    <div className="text-slate-500">No NS records resolved</div>
                  )}
                </div>
              </div>

              <div className="bg-slate-950/50 p-4 rounded-lg border border-slate-800 text-xs space-y-2">
                <span className="text-slate-400 font-semibold uppercase text-[10px] tracking-wider">
                  Resolved IP Addresses ({dossier.ipAddresses.length})
                </span>
                <div className="font-mono text-slate-300 space-y-1">
                  {dossier.ipAddresses.length > 0 ? (
                    dossier.ipAddresses.map((ip, idx) => <div key={idx} className="truncate">• {ip}</div>)
                  ) : (
                    <div className="text-slate-500">No A/AAAA records resolved</div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Typosquatting & Lookalike Impersonation Matrix */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-xl space-y-4 p-5">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="w-5 h-5 text-amber-400" />
                <h2 className="text-base font-bold text-white tracking-tight">
                  Typosquatting & Homoglyph Threat Matrix
                </h2>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                {dossier.typosquattingAlerts.length} variations generated
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 uppercase text-[10px] font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Variant Domain</th>
                    <th className="py-3 px-4">Attack Type</th>
                    <th className="py-3 px-4">Target Trademark</th>
                    <th className="py-3 px-4">Similarity</th>
                    <th className="py-3 px-4">Risk Level</th>
                    <th className="py-3 px-4">Technical Explanation</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {dossier.typosquattingAlerts.map((match: TyposquattingMatch, idx: number) => (
                    <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 text-slate-200 font-bold">
                        {match.variant}
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                          {match.type}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 font-sans">
                        {match.targetBrand}
                      </td>
                      <td className="py-3 px-4 font-bold text-cyan-400">
                        {match.similarityScore}%
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          match.riskLevel === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                          match.riskLevel === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                          'bg-slate-800 text-slate-400'
                        }`}>
                          {match.riskLevel}
                        </span>
                      </td>
                      <td className="py-3 px-4 max-w-[280px] text-[11px] text-slate-400 font-sans">
                        {match.explanation}
                      </td>
                      <td className="py-3 px-4 text-right font-sans">
                        <button
                          onClick={() => copyToClipboard(match.variant)}
                          className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors inline-flex items-center"
                          title="Copy variant domain"
                        >
                          {copiedVariant === match.variant ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Historical Scans on this Domain */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-xl p-5 space-y-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              <span>Historical URL Analyses for {dossier.domain}</span>
            </h3>

            {dossier.recentAnalyses.length === 0 ? (
              <p className="text-xs text-slate-500 py-3 text-center">No individual URL analyses recorded on this domain yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/60 text-slate-400 uppercase text-[10px] font-semibold border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4">Scanned URL</th>
                      <th className="py-3 px-4">Verdict</th>
                      <th className="py-3 px-4">Risk Score</th>
                      <th className="py-3 px-4">Scanned At</th>
                      <th className="py-3 px-4 text-right">Investigation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {dossier.recentAnalyses.map((item) => (
                      <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-4 max-w-[320px] truncate text-slate-200" title={item.url}>
                          {item.url}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            item.verdict === 'PHISHING' ? 'bg-rose-500/20 text-rose-300' :
                            item.verdict === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-300' :
                            'bg-emerald-500/20 text-emerald-300'
                          }`}>
                            {item.verdict}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-bold">
                          {item.riskScore.toFixed(1)}
                        </td>
                        <td className="py-3 px-4 text-slate-400 text-[11px]">
                          {new Date(item.createdAt).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 text-right font-sans">
                          <button
                            onClick={() => navigate(`/analysis/${item.id}`)}
                            className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 hover:underline text-xs"
                          >
                            <span>Inspect</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : !loading && (
        <div className="bg-slate-900/40 border border-slate-800/80 rounded-xl p-12 text-center space-y-4">
          <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 mx-auto flex items-center justify-center">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white">Enter a Domain to Inspect</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto mt-1">
              Search for any domain (e.g. <span className="text-indigo-400 font-mono">google.com</span> or <span className="text-indigo-400 font-mono">paypa1-security.com</span>) to inspect its full registration dossier and typosquatting risk profile.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
