import React, { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { AnalysisSummary } from '@phishnetra/shared';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  Activity,
  ArrowUpRight,
  Clock,
  Radio,
  RefreshCw,
  Filter,
  Network,
  Shield,
  Layers,
  Sparkles,
  Zap
} from 'lucide-react';

export const DashboardPage: React.FC = () => {
  const [history, setHistory] = useState<AnalysisSummary[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'PHISHING' | 'SUSPICIOUS' | 'SAFE'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const fetchHistory = async (showRefreshIndicator = false) => {
    if (showRefreshIndicator) setIsRefreshing(true);
    try {
      const data = await api.getHistory(50, 0);
      setHistory(data.items);
      setTotalCount(data.total);
    } catch (err) {
      console.error('Failed to load analysis history:', err);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  // Compute aggregate stats from history
  const threatCount = useMemo(() => history.filter(h => h.verdict === 'PHISHING').length, [history]);
  const suspiciousCount = useMemo(() => history.filter(h => h.verdict === 'SUSPICIOUS').length, [history]);
  const safeCount = useMemo(() => history.filter(h => h.verdict === 'SAFE').length, [history]);
  const avgRisk = useMemo(() => {
    return history.length > 0
      ? (history.reduce((acc, h) => acc + h.riskScore, 0) / history.length).toFixed(1)
      : '0.0';
  }, [history]);

  // Filtered history list
  const filteredHistory = useMemo(() => {
    return history.filter(item => {
      const matchesVerdict = statusFilter === 'ALL' || item.verdict === statusFilter;
      const matchesSearch = !searchQuery.trim() || item.url.toLowerCase().includes(searchQuery.toLowerCase().trim());
      return matchesVerdict && matchesSearch;
    });
  }, [history, statusFilter, searchQuery]);

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case 'SAFE':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 shadow-sm shadow-emerald-500/10">
            <ShieldCheck className="w-3 h-3 text-emerald-400" />
            <span>SAFE</span>
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30 shadow-sm shadow-amber-500/10">
            <Activity className="w-3 h-3 text-amber-300" />
            <span>SUSPICIOUS</span>
          </span>
        );
      case 'PHISHING':
      default:
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm shadow-rose-500/10">
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            <span>PHISHING</span>
          </span>
        );
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 animate-fadeIn">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Threat Intelligence Console
            </h1>
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
              v2.4.0 SOC
            </span>
          </div>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 flex items-center space-x-2 font-mono">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>Enterprise Zero-Trust SOC Platform • 20 Defense Engines Active</span>
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            type="button"
            onClick={() => fetchHistory(true)}
            disabled={isRefreshing}
            className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 transition-all disabled:opacity-50"
            title="Refresh Analysis Feed"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>

          <Link
            to="/analyze"
            className="inline-flex items-center justify-center space-x-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/25 transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Search className="w-4 h-4" />
            <span>New URL Threat Analysis</span>
          </Link>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Scans Card */}
        <div className="glass-panel glass-card-hover p-5 rounded-2xl border-slate-800/80 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Total Scans
            </span>
            <div className="text-2xl sm:text-3xl font-extrabold font-mono text-white mt-1">
              {totalCount}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-1">
              Audit trail logged
            </div>
          </div>
          <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center shadow-inner">
            <Activity className="w-6 h-6 text-cyan-400" />
          </div>
        </div>

        {/* Threats Detected Card */}
        <div className="glass-panel glass-card-hover p-5 rounded-2xl border-slate-800/80 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Threats Detected
            </span>
            <div className="text-2xl sm:text-3xl font-extrabold font-mono text-rose-400 mt-1">
              {threatCount}
            </div>
            <div className="text-[10px] text-rose-400/80 font-mono mt-1">
              {totalCount > 0 ? `${((threatCount / totalCount) * 100).toFixed(0)}% attack ratio` : 'Zero anomalies'}
            </div>
          </div>
          <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/25 flex items-center justify-center shadow-inner">
            <ShieldAlert className="w-6 h-6 text-rose-400" />
          </div>
        </div>

        {/* Safe Verified Card */}
        <div className="glass-panel glass-card-hover p-5 rounded-2xl border-slate-800/80 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Safe Verified
            </span>
            <div className="text-2xl sm:text-3xl font-extrabold font-mono text-emerald-400 mt-1">
              {safeCount}
            </div>
            <div className="text-[10px] text-emerald-400/80 font-mono mt-1">
              {totalCount > 0 ? `${((safeCount / totalCount) * 100).toFixed(0)}% clean traffic` : 'Zero malicious'}
            </div>
          </div>
          <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center shadow-inner">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
          </div>
        </div>

        {/* Average Risk Score Card */}
        <div className="glass-panel glass-card-hover p-5 rounded-2xl border-slate-800/80 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Average Risk Score
            </span>
            <div className="text-2xl sm:text-3xl font-extrabold font-mono text-amber-400 mt-1">
              {avgRisk}
            </div>
            <div className="text-[10px] text-amber-400/80 font-mono mt-1">
              Scale 0 - 100 risk
            </div>
          </div>
          <div className="w-12 h-12 rounded-2xl bg-amber-500/10 border border-amber-500/25 flex items-center justify-center shadow-inner">
            <Clock className="w-6 h-6 text-amber-400" />
          </div>
        </div>
      </div>

      {/* Quick Access Defense Hub */}
      <div className="glass-panel p-4 rounded-2xl border-slate-800/80">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
          <div className="flex items-center space-x-2 text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
            <Zap className="w-3.5 h-3.5 text-cyan-400" />
            <span>Active SOC Operations Hub</span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            Direct navigation across zero-trust defense sub-systems
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-2.5">
          <Link
            to="/cti-exchange"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-cyan-500/40 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-bold text-cyan-400 group-hover:text-cyan-300">CTI Exchange</span>
              <ArrowUpRight className="w-3 h-3 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[10px] text-slate-400 font-mono">TAXII 2.1 & STIX Feed</span>
          </Link>

          <Link
            to="/bgp-integrity"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-cyan-500/40 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-bold text-cyan-400 group-hover:text-cyan-300">BGP Radar</span>
              <ArrowUpRight className="w-3 h-3 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[10px] text-slate-400 font-mono">RPKI Route Hijacking</span>
          </Link>

          <Link
            to="/fido2-guard"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-cyan-500/40 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-bold text-cyan-400 group-hover:text-cyan-300">FIDO2 Guard</span>
              <ArrowUpRight className="w-3 h-3 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[10px] text-slate-400 font-mono">WebAuthn Channel-ID</span>
          </Link>

          <Link
            to="/rbi"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-cyan-500/40 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-bold text-cyan-400 group-hover:text-cyan-300">RBI Sandbox</span>
              <ArrowUpRight className="w-3 h-3 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[10px] text-slate-400 font-mono">Isolated Browser DOM</span>
          </Link>

          <Link
            to="/threat-graph"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-cyan-500/40 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-bold text-cyan-400 group-hover:text-cyan-300">Threat Graph</span>
              <ArrowUpRight className="w-3 h-3 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[10px] text-slate-400 font-mono">Neo4j Infrastructure</span>
          </Link>

          <Link
            to="/takedowns"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-cyan-500/40 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-bold text-cyan-400 group-hover:text-cyan-300">SOAR Takedown</span>
              <ArrowUpRight className="w-3 h-3 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[10px] text-slate-400 font-mono">Abuse Dispatch & RPZ</span>
          </Link>
        </div>
      </div>

      {/* Analysis History Section */}
      <div className="glass-panel rounded-2xl border-slate-800/90 overflow-hidden shadow-2xl">
        <div className="p-5 sm:p-6 border-b border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h2 className="text-base sm:text-lg font-bold text-white flex items-center space-x-2">
                <span>Recent Analysis Feed</span>
                <span className="text-xs font-mono font-normal text-slate-500">({filteredHistory.length} matches)</span>
              </h2>
              <p className="text-xs text-slate-400">
                Audit trail of scanned target URLs, multi-layer heuristics, and verdict outcomes
              </p>
            </div>

            {/* Quick URL Search Box */}
            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by URL or domain..."
                className="w-full bg-slate-950/90 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
              />
            </div>
          </div>

          {/* Verdict Filter Pills */}
          <div className="flex items-center space-x-2 pt-1 border-t border-slate-800/60">
            <span className="text-[11px] font-mono text-slate-400 flex items-center space-x-1 mr-1">
              <Filter className="w-3 h-3 text-cyan-400" />
              <span>Filter:</span>
            </span>
            <button
              type="button"
              onClick={() => setStatusFilter('ALL')}
              className={`px-3 py-1 rounded-lg text-xs font-mono transition-all ${
                statusFilter === 'ALL'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                  : 'bg-slate-950/60 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              All ({history.length})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter('PHISHING')}
              className={`px-3 py-1 rounded-lg text-xs font-mono transition-all ${
                statusFilter === 'PHISHING'
                  ? 'bg-rose-500/25 text-rose-300 border border-rose-500/50 font-bold'
                  : 'bg-slate-950/60 text-slate-400 hover:text-rose-300 border border-slate-800'
              }`}
            >
              Phishing ({threatCount})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter('SUSPICIOUS')}
              className={`px-3 py-1 rounded-lg text-xs font-mono transition-all ${
                statusFilter === 'SUSPICIOUS'
                  ? 'bg-amber-500/25 text-amber-300 border border-amber-500/50 font-bold'
                  : 'bg-slate-950/60 text-slate-400 hover:text-amber-300 border border-slate-800'
              }`}
            >
              Suspicious ({suspiciousCount})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter('SAFE')}
              className={`px-3 py-1 rounded-lg text-xs font-mono transition-all ${
                statusFilter === 'SAFE'
                  ? 'bg-emerald-500/25 text-emerald-300 border border-emerald-500/50 font-bold'
                  : 'bg-slate-950/60 text-slate-400 hover:text-emerald-300 border border-slate-800'
              }`}
            >
              Safe ({safeCount})
            </button>
          </div>
        </div>

        {isLoading ? (
          <div className="p-16 text-center text-slate-400 text-xs">
            <Activity className="w-7 h-7 text-cyan-400 animate-spin mx-auto mb-3" />
            <span className="font-mono">Synchronizing telemetry intelligence feed...</span>
          </div>
        ) : filteredHistory.length === 0 ? (
          <div className="p-16 text-center text-slate-400 space-y-3">
            <Search className="w-10 h-10 text-slate-700 mx-auto" />
            <p className="text-sm font-medium text-slate-300">
              {searchQuery || statusFilter !== 'ALL'
                ? 'No analysis records match your filter criteria.'
                : 'No URL analyses logged yet.'}
            </p>
            {searchQuery || statusFilter !== 'ALL' ? (
              <button
                type="button"
                onClick={() => {
                  setSearchQuery('');
                  setStatusFilter('ALL');
                }}
                className="inline-block text-xs font-semibold px-4 py-2 rounded-lg bg-slate-800 text-cyan-300 hover:bg-slate-700 transition-colors"
              >
                Clear Filters
              </button>
            ) : (
              <Link
                to="/analyze"
                className="inline-block text-xs font-semibold px-4 py-2 rounded-lg bg-slate-800 text-cyan-300 hover:bg-slate-700 transition-colors"
              >
                Analyze your first URL
              </Link>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs sm:text-sm">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-3.5 px-5">Target URL</th>
                  <th className="py-3.5 px-4">Verdict</th>
                  <th className="py-3.5 px-4">Risk Score</th>
                  <th className="py-3.5 px-4">Timestamp</th>
                  <th className="py-3.5 px-4 text-right">Investigation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredHistory.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="py-3.5 px-5 font-mono text-slate-200 max-w-xs sm:max-w-md truncate group-hover:text-cyan-300 transition-colors">
                      {item.url}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getVerdictBadge(item.verdict)}
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold">
                      <span className={item.riskScore >= 60 ? 'text-rose-400 font-extrabold' : item.riskScore >= 30 ? 'text-amber-400' : 'text-emerald-400'}>
                        {item.riskScore.toFixed(1)}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-xs whitespace-nowrap">
                      {new Date(item.createdAt).toLocaleDateString()} {new Date(item.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <Link
                        to={`/analysis/${item.id}`}
                        className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-slate-800/90 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-slate-700/60 hover:border-cyan-500/40 transition-all text-xs font-semibold"
                      >
                        <span>Inspect</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

