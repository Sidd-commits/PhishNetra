import React, { useState, useEffect } from 'react';
import {
  Flame,
  ShieldAlert,
  Zap,
  Download,
  ExternalLink,
  Search,
  Filter,
  Globe,
  Server,
  Building,
  Tag,
  Clock,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Network
} from 'lucide-react';
import { ThreatCampaign } from '@phishnetra/shared';
import axios from 'axios';
import { Link } from 'react-router-dom';

const API_BASE = 'http://localhost:5000/api';

export const CampaignsPage: React.FC = () => {
  const [campaigns, setCampaigns] = useState<ThreatCampaign[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [clustering, setClustering] = useState<boolean>(false);
  const [clusterNotice, setClusterNotice] = useState<string | null>(null);

  const fetchCampaigns = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/campaigns?status=${statusFilter}`);
      if (res.data.success) {
        setCampaigns(res.data.data);
      }
    } catch (err) {
      console.error('Failed to fetch threat campaigns:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRunClustering = async () => {
    setClustering(true);
    setClusterNotice(null);
    try {
      const res = await axios.post(`${API_BASE}/campaigns/cluster`);
      if (res.data.success) {
        const result = res.data.data;
        setClusterNotice(`Successfully analyzed infrastructure. Formed ${result.newCampaignsCreated} new threat campaign cluster(s).`);
        await fetchCampaigns();
      }
    } catch (err: any) {
      setClusterNotice(`Clustering error: ${err.message}`);
    } finally {
      setClustering(false);
    }
  };

  const handleDownloadStix = (campaignId: string) => {
    window.open(`${API_BASE}/campaigns/${campaignId}/stix`, '_blank');
  };

  useEffect(() => {
    fetchCampaigns();
  }, [statusFilter]);

  const filteredCampaigns = campaigns.filter((c) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.name.toLowerCase().includes(q) ||
      c.targetedBrands.some((b) => b.toLowerCase().includes(q)) ||
      c.iocs.domains.some((d) => d.toLowerCase().includes(q)) ||
      c.iocs.asns.some((a) => a.toLowerCase().includes(q))
    );
  });

  // Calculate statistics
  const totalDomains = campaigns.reduce((acc, c) => acc + c.domainCount, 0);
  const totalIps = campaigns.reduce((acc, c) => acc + c.ipCount, 0);
  const criticalCount = campaigns.filter((c) => c.riskLevel === 'CRITICAL').length;
  const allBrands = Array.from(new Set(campaigns.flatMap((c) => c.targetedBrands)));

  return (
    <div className="min-h-[calc(100vh-4rem)] bg-slate-950 text-slate-100 py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Header Banner */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
          <div>
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-rose-500 to-amber-600 p-[1px] shadow-lg shadow-rose-500/20">
                <div className="w-full h-full bg-slate-950 rounded-[11px] flex items-center justify-center">
                  <Flame className="w-5 h-5 text-rose-400" />
                </div>
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                  Threat Campaign & Intrusion Set Hub
                  <span className="text-[10px] uppercase font-bold tracking-widest px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-300 border border-rose-500/20">
                    M6 • Campaign Engine
                  </span>
                </h1>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Autonomous threat ring correlation, brand impersonation aggregation, and STIX 2.1 intelligence sharing
                </p>
              </div>
            </div>
          </div>

          {/* Top Actions */}
          <div className="flex items-center space-x-3 w-full md:w-auto">
            <button
              onClick={handleRunClustering}
              disabled={clustering}
              className="flex-1 md:flex-none flex items-center justify-center space-x-2 px-4 py-2.5 rounded-xl text-xs font-bold bg-gradient-to-r from-rose-500 to-red-600 hover:from-rose-400 hover:to-red-500 text-white shadow-lg shadow-rose-500/20 transition-all cursor-pointer"
            >
              <Zap className={`w-4 h-4 ${clustering ? 'animate-spin' : ''}`} />
              <span>{clustering ? 'Correlating Graphs...' : 'Run Autonomous Clustering'}</span>
            </button>

            <Link
              to="/graph"
              className="flex items-center space-x-2 px-4 py-2.5 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition-colors"
            >
              <Network className="w-4 h-4 text-cyan-400" />
              <span>Explore Graph</span>
            </Link>
          </div>
        </div>

        {/* Cluster Notice */}
        {clusterNotice && (
          <div className="px-4 py-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs flex items-center justify-between">
            <span className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              {clusterNotice}
            </span>
            <button onClick={() => setClusterNotice(null)} className="text-emerald-400 hover:text-white font-bold">✕</button>
          </div>
        )}

        {/* Statistics Metric Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-5 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Campaigns</span>
              <Flame className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold text-white font-mono mt-2">{campaigns.length}</div>
            <div className="text-[11px] text-slate-500 font-mono mt-1">Autonomous threat rings</div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-5 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Correlated Domains</span>
              <Globe className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-cyan-300 font-mono mt-2">{totalDomains}</div>
            <div className="text-[11px] text-slate-500 font-mono mt-1">Under active monitoring</div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-5 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Targeted Brands</span>
              <Tag className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-amber-300 font-mono mt-2">{allBrands.length}</div>
            <div className="text-[11px] text-slate-500 font-mono mt-1">{allBrands.slice(0, 3).join(', ') || 'None'}</div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-5 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Critical Severity</span>
              <ShieldAlert className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-rose-400 font-mono mt-2">{criticalCount}</div>
            <div className="text-[11px] text-slate-500 font-mono mt-1">High-risk infrastructure</div>
          </div>
        </div>

        {/* Filter and Search Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-slate-900/40 p-4 rounded-2xl border border-slate-800/60">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search campaigns, brands, IOCs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-rose-500 font-mono"
            />
          </div>

          <div className="flex items-center space-x-2 w-full sm:w-auto justify-end">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-xs text-slate-400">Status:</span>
            {['ALL', 'ACTIVE', 'DORMANT', 'NEUTRALIZED'].map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`text-xs font-semibold px-3 py-1.5 rounded-lg border transition-all ${
                  statusFilter === status
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-sm'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>

        {/* Campaign List Cards */}
        {loading ? (
          <div className="py-20 text-center text-slate-500 flex flex-col items-center">
            <RefreshCw className="w-8 h-8 animate-spin text-rose-500 mb-3" />
            <p className="text-sm font-semibold">Correlating Threat Infrastructure...</p>
          </div>
        ) : filteredCampaigns.length === 0 ? (
          <div className="py-16 text-center border border-dashed border-slate-800 rounded-2xl bg-slate-950/40">
            <Flame className="w-10 h-10 text-slate-600 mx-auto mb-3" />
            <h3 className="text-sm font-bold text-slate-300">No Threat Campaigns Found</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              Run the Autonomous Clustering engine above to analyze scanned phishing domains and group infrastructure.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {filteredCampaigns.map((campaign) => (
              <div
                key={campaign.id}
                className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6 backdrop-blur-md hover:border-slate-700 transition-all flex flex-col justify-between shadow-xl"
              >
                <div>
                  {/* Top Card Bar */}
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div>
                      <div className="flex items-center space-x-2 mb-1">
                        <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                          {campaign.status}
                        </span>
                        <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                          campaign.riskLevel === 'CRITICAL' ? 'bg-red-500/20 text-red-300' : 'bg-amber-500/20 text-amber-300'
                        }`}>
                          {campaign.riskLevel} RISK
                        </span>
                      </div>
                      <h3 className="text-base font-bold text-white font-mono tracking-tight">
                        {campaign.name}
                      </h3>
                    </div>

                    <div className="text-right">
                      <div className="text-xs font-mono font-bold text-rose-400">
                        {campaign.severityScore}/100
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono">Severity</div>
                    </div>
                  </div>

                  {/* Description */}
                  <p className="text-xs text-slate-400 leading-relaxed mb-4">
                    {campaign.description}
                  </p>

                  {/* Targeted Brands */}
                  <div className="flex items-center flex-wrap gap-1.5 mb-4">
                    <span className="text-[11px] font-semibold text-slate-500 flex items-center gap-1 mr-1">
                      <Tag className="w-3 h-3 text-amber-400" /> Targets:
                    </span>
                    {campaign.targetedBrands.length === 0 ? (
                      <span className="text-xs text-slate-500">Unspecified</span>
                    ) : (
                      campaign.targetedBrands.map((b) => (
                        <span
                          key={b}
                          className="text-[11px] font-bold px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-300 border border-amber-500/20"
                        >
                          {b}
                        </span>
                      ))
                    )}
                  </div>

                  {/* IOC Infrastructure Matrix */}
                  <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800/80 mb-4 space-y-2">
                    <div className="flex items-center justify-between text-xs text-slate-400">
                      <span className="flex items-center gap-1.5">
                        <Globe className="w-3.5 h-3.5 text-cyan-400" />
                        <strong>Domains ({campaign.iocs.domains.length}):</strong>
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {campaign.iocs.domains.slice(0, 4).map((d) => (
                        <span key={d} className="text-[11px] font-mono text-cyan-300 bg-cyan-500/10 px-2 py-0.5 rounded">
                          {d}
                        </span>
                      ))}
                      {campaign.iocs.domains.length > 4 && (
                        <span className="text-[10px] text-slate-500 px-1 py-0.5">
                          +{campaign.iocs.domains.length - 4} more
                        </span>
                      )}
                    </div>

                    {campaign.iocs.asns.length > 0 && (
                      <div className="pt-2 border-t border-slate-900 flex items-center gap-2 text-xs text-slate-400">
                        <Building className="w-3.5 h-3.5 text-purple-400" />
                        <span>ASNs:</span>
                        <div className="flex gap-1">
                          {campaign.iocs.asns.map((a) => (
                            <span key={a} className="text-[10px] font-mono text-purple-300 bg-purple-500/10 px-1.5 py-0.2 rounded">
                              {a}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Card Footer Actions */}
                <div className="flex items-center justify-between pt-4 border-t border-slate-800/80">
                  <div className="flex items-center space-x-1.5 text-[11px] font-mono text-slate-500">
                    <Clock className="w-3.5 h-3.5" />
                    <span>First Seen: {new Date(campaign.firstSeen).toLocaleDateString()}</span>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => handleDownloadStix(campaign.id)}
                      className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                      title="Download STIX 2.1 JSON"
                    >
                      <Download className="w-3.5 h-3.5 text-cyan-400" />
                      <span>STIX 2.1</span>
                    </button>

                    <Link
                      to={`/graph?domain=${encodeURIComponent(campaign.iocs.domains[0] || '')}`}
                      className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 transition-colors"
                    >
                      <span>Graph</span>
                      <ExternalLink className="w-3 h-3" />
                    </Link>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
