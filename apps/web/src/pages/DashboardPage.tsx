import React, { useEffect, useState } from 'react';
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
  Radio
} from 'lucide-react';

export const DashboardPage: React.FC = () => {
  const [history, setHistory] = useState<AnalysisSummary[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const data = await api.getHistory(20, 0);
        setHistory(data.items);
        setTotalCount(data.total);
      } catch (err) {
        console.error('Failed to load analysis history:', err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchHistory();
  }, []);

  // Compute aggregate stats from history
  const threatCount = history.filter(h => h.verdict === 'PHISHING').length;
  const safeCount = history.filter(h => h.verdict === 'SAFE').length;
  const avgRisk = history.length > 0
    ? (history.reduce((acc, h) => acc + h.riskScore, 0) / history.length).toFixed(1)
    : '0.0';

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case 'SAFE':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3 h-3" />
            <span>SAFE</span>
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
            <Activity className="w-3 h-3" />
            <span>SUSPICIOUS</span>
          </span>
        );
      case 'PHISHING':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
            <ShieldAlert className="w-3 h-3" />
            <span>PHISHING</span>
          </span>
        );
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Threat Intelligence Console
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 flex items-center space-x-2 font-mono">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>Zero-Trust Analysis Pipeline • Milestone 1 Active</span>
          </p>
        </div>

        <Link
          to="/analyze"
          className="inline-flex items-center justify-center space-x-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/20 transition-all hover:scale-[1.02]"
        >
          <Search className="w-4 h-4" />
          <span>New URL Threat Analysis</span>
        </Link>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-panel p-5 rounded-2xl border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Total Scans
            </span>
            <div className="text-2xl sm:text-3xl font-extrabold font-mono text-white mt-1">
              {totalCount}
            </div>
          </div>
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
        </div>

        <div className="glass-panel p-5 rounded-2xl border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Threats Detected
            </span>
            <div className="text-2xl sm:text-3xl font-extrabold font-mono text-rose-400 mt-1">
              {threatCount}
            </div>
          </div>
          <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
          </div>
        </div>

        <div className="glass-panel p-5 rounded-2xl border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Safe Verified
            </span>
            <div className="text-2xl sm:text-3xl font-extrabold font-mono text-emerald-400 mt-1">
              {safeCount}
            </div>
          </div>
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
        </div>

        <div className="glass-panel p-5 rounded-2xl border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Average Risk Score
            </span>
            <div className="text-2xl sm:text-3xl font-extrabold font-mono text-amber-400 mt-1">
              {avgRisk}
            </div>
          </div>
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
            <Clock className="w-5 h-5 text-amber-400" />
          </div>
        </div>
      </div>

      {/* Analysis History Section */}
      <div className="glass-panel rounded-2xl border-slate-800/90 overflow-hidden">
        <div className="p-5 sm:p-6 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base sm:text-lg font-bold text-white">
              Recent Analysis Feed
            </h2>
            <p className="text-xs text-slate-400">
              Audit trail of scanned target URLs and verdict outcomes
            </p>
          </div>
          <Link
            to="/analyze"
            className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors flex items-center space-x-1"
          >
            <span>Scan URL</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {isLoading ? (
          <div className="p-12 text-center text-slate-400 text-xs">
            <Activity className="w-6 h-6 text-cyan-400 animate-spin mx-auto mb-2" />
            <span>Loading telemetry history...</span>
          </div>
        ) : history.length === 0 ? (
          <div className="p-12 text-center text-slate-400 space-y-3">
            <Search className="w-10 h-10 text-slate-600 mx-auto" />
            <p className="text-sm font-medium">No URL analyses logged yet.</p>
            <Link
              to="/analyze"
              className="inline-block text-xs font-semibold px-4 py-2 rounded-lg bg-slate-800 text-cyan-300 hover:bg-slate-700 transition-colors"
            >
              Analyze your first URL
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs sm:text-sm">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-5">Target URL</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Investigation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {history.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-5 font-mono text-slate-200 max-w-xs sm:max-w-md truncate">
                      {item.url}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getVerdictBadge(item.verdict)}
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold">
                      <span className={item.riskScore >= 60 ? 'text-rose-400' : item.riskScore >= 30 ? 'text-amber-400' : 'text-emerald-400'}>
                        {item.riskScore.toFixed(1)}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-xs whitespace-nowrap">
                      {new Date(item.createdAt).toLocaleDateString()} {new Date(item.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <Link
                        to={`/analysis/${item.id}`}
                        className="inline-flex items-center space-x-1 px-3 py-1 rounded-lg bg-slate-800 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 transition-colors text-xs font-semibold"
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
