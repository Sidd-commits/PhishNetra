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
  RefreshCw,
  Filter
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
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>SAFE</span>
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/20">
            <Activity className="w-3.5 h-3.5 text-amber-300" />
            <span>SUSPICIOUS</span>
          </span>
        );
      case 'PHISHING':
      default:
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/15 text-rose-300 border border-rose-500/30">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
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
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Threat Overview
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Real-time phishing telemetry, automated detections, and threat response.
          </p>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            type="button"
            onClick={() => fetchHistory(true)}
            disabled={isRefreshing}
            className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors disabled:opacity-50"
            title="Refresh feed"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>

          <Link
            to="/analyze"
            className="inline-flex items-center justify-center space-x-2 px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs sm:text-sm shadow-md transition-all active:scale-[0.98]"
          >
            <Search className="w-4 h-4" />
            <span>Analyze URL</span>
          </Link>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Scans Card */}
        <div className="glass-panel p-5 rounded-2xl border-slate-800/80 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 font-medium">
              Total Scans
            </span>
            <div className="text-2xl sm:text-3xl font-bold text-white mt-1">
              {totalCount.toLocaleString()}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              All-time analyzed targets
            </div>
          </div>
          <div className="w-10 h-10 rounded-xl bg-slate-800/70 border border-slate-700/60 flex items-center justify-center">
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
        </div>

        {/* Threats Detected Card */}
        <div className="glass-panel p-5 rounded-2xl border-slate-800/80 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 font-medium">
              Threats Detected
            </span>
            <div className="text-2xl sm:text-3xl font-bold text-rose-400 mt-1">
              {threatCount}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Confirmed phishing
            </div>
          </div>
          <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
          </div>
        </div>

        {/* Safe Verified Card */}
        <div className="glass-panel p-5 rounded-2xl border-slate-800/80 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 font-medium">
              Safe Verified
            </span>
            <div className="text-2xl sm:text-3xl font-bold text-emerald-400 mt-1">
              {safeCount}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Benign traffic
            </div>
          </div>
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
        </div>

        {/* Average Risk Score Card */}
        <div className="glass-panel p-5 rounded-2xl border-slate-800/80 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 font-medium">
              Average Risk Score
            </span>
            <div className="text-2xl sm:text-3xl font-bold text-white mt-1">
              {avgRisk}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Overall fleet risk
            </div>
          </div>
          <div className="w-10 h-10 rounded-xl bg-slate-800/70 border border-slate-700/60 flex items-center justify-center">
            <Clock className="w-5 h-5 text-amber-400" />
          </div>
        </div>
      </div>

      {/* Security Modules Hub */}
      <div className="glass-panel p-5 rounded-2xl border-slate-800/80 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
          <h2 className="text-sm font-semibold text-slate-200">
            Security Modules
          </h2>
          <span className="text-xs text-slate-400">
            Direct access to specialized detection and response tools
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
          <Link
            to="/cti-exchange"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-slate-700 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors">Threat Feeds</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[11px] text-slate-400">TAXII 2.1 & STIX</span>
          </Link>

          <Link
            to="/bgp-integrity"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-slate-700 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors">Route Radar</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[11px] text-slate-400">BGP & RPKI health</span>
          </Link>

          <Link
            to="/fido2-guard"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-slate-700 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors">Credential Guard</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[11px] text-slate-400">FIDO2 protection</span>
          </Link>

          <Link
            to="/rbi"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-slate-700 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors">Browser Sandbox</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[11px] text-slate-400">Isolated DOM preview</span>
          </Link>

          <Link
            to="/threat-graph"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-slate-700 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors">Threat Graph</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[11px] text-slate-400">Infrastructure map</span>
          </Link>

          <Link
            to="/takedowns"
            className="p-3 rounded-xl bg-slate-950/60 hover:bg-slate-900 border border-slate-800/80 hover:border-slate-700 text-slate-300 hover:text-white transition-all text-xs flex flex-col space-y-1 group"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors">Takedown Center</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <span className="text-[11px] text-slate-400">Automated dispatch</span>
          </Link>
        </div>
      </div>

      {/* Analysis History Section */}
      <div className="glass-panel rounded-2xl border-slate-800/90 overflow-hidden shadow-xl">
        <div className="p-5 sm:p-6 border-b border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold text-white">
                Recent Scans
              </h2>
              <p className="text-xs text-slate-400">
                Log of evaluated target URLs and security verdicts
              </p>
            </div>

            {/* URL Search Box */}
            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by URL or domain..."
                className="w-full bg-slate-950/90 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-sans"
              />
            </div>
          </div>

          {/* Verdict Filter Buttons */}
          <div className="flex items-center space-x-2 pt-1 border-t border-slate-800/60">
            <span className="text-xs text-slate-400 mr-1">Status:</span>
            <button
              type="button"
              onClick={() => setStatusFilter('ALL')}
              className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${
                statusFilter === 'ALL'
                  ? 'bg-slate-800 text-white border border-slate-700'
                  : 'bg-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({history.length})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter('PHISHING')}
              className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${
                statusFilter === 'PHISHING'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                  : 'bg-transparent text-slate-400 hover:text-rose-300'
              }`}
            >
              Phishing ({threatCount})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter('SUSPICIOUS')}
              className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${
                statusFilter === 'SUSPICIOUS'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                  : 'bg-transparent text-slate-400 hover:text-amber-300'
              }`}
            >
              Suspicious ({suspiciousCount})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter('SAFE')}
              className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${
                statusFilter === 'SAFE'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-transparent text-slate-400 hover:text-emerald-300'
              }`}
            >
              Safe ({safeCount})
            </button>
          </div>
        </div>

        {isLoading ? (
          <div className="p-16 text-center text-slate-400 text-xs">
            <Activity className="w-7 h-7 text-cyan-400 animate-spin mx-auto mb-3" />
            <span>Loading telemetry data...</span>
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
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 text-xs font-medium uppercase tracking-wider">
                <tr>
                  <th className="py-3.5 px-5">Target URL</th>
                  <th className="py-3.5 px-4">Verdict</th>
                  <th className="py-3.5 px-4">Risk Score</th>
                  <th className="py-3.5 px-4">Timestamp</th>
                  <th className="py-3.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredHistory.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="py-3.5 px-5 text-slate-200 text-xs font-mono max-w-xs sm:max-w-md truncate group-hover:text-cyan-300 transition-colors">
                      {item.url}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getVerdictBadge(item.verdict)}
                    </td>
                    <td className="py-3.5 px-4 text-xs font-semibold">
                      <span className={item.riskScore >= 60 ? 'text-rose-400' : item.riskScore >= 30 ? 'text-amber-400' : 'text-emerald-400'}>
                        {item.riskScore.toFixed(1)}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-xs whitespace-nowrap">
                      {new Date(item.createdAt).toLocaleDateString()} {new Date(item.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <Link
                        to={`/analysis/${item.id}`}
                        className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60 transition-colors text-xs font-medium"
                      >
                        <span>Inspect</span>
                        <ArrowUpRight className="w-3 h-3 text-slate-400" />
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


