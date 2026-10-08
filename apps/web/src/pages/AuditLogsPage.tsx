import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import { AuditLogEntry, AuditLogCategory, AuditLogSeverity } from '@phishnetra/shared';
import {
  FileText,
  Search,
  Download,
  Filter,
  ShieldAlert,
  User,
  Activity,
  Terminal,
  Clock,
  Radio,
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  RefreshCw
} from 'lucide-react';

export const AuditLogsPage: React.FC = () => {
  const { showToast } = useToast();
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [page, setPage] = useState<number>(0);
  const limit = 25;

  useEffect(() => {
    fetchLogs();
  }, [selectedCategory, selectedSeverity, page]);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const res = await api.getAuditLogs({
        category: selectedCategory !== 'ALL' ? selectedCategory : undefined,
        severity: selectedSeverity !== 'ALL' ? selectedSeverity : undefined,
        search: searchQuery ? searchQuery : undefined,
        limit,
        offset: page * limit
      });
      setLogs(res.logs);
      setTotal(res.total);
    } catch (err: any) {
      showToast('error', 'Failed to fetch audit logs', err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(0);
    fetchLogs();
  };

  const handleExportCsv = () => {
    const csvUrl = `http://localhost:5000/api/audit-logs/export${
      selectedCategory !== 'ALL' ? `?category=${selectedCategory}` : ''
    }`;
    window.open(csvUrl, '_blank');
    showToast('success', 'Exporting Audit Trail', 'Downloading audit trail CSV report');
  };

  const getSeverityBadge = (severity: AuditLogSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <AlertOctagon className="w-3 h-3" />
            CRITICAL
          </span>
        );
      case 'WARNING':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-3 h-3" />
            WARNING
          </span>
        );
      case 'INFO':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <CheckCircle2 className="w-3 h-3" />
            INFO
          </span>
        );
    }
  };

  const getCategoryBadge = (cat: AuditLogCategory) => {
    const colors: Record<string, string> = {
      AUTH: 'bg-indigo-500/10 text-indigo-300 border-indigo-500/20',
      ANALYSIS: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20',
      CASE: 'bg-amber-500/10 text-amber-300 border-amber-500/20',
      REMEDIATION: 'bg-rose-500/10 text-rose-300 border-rose-500/20',
      CONFIG: 'bg-teal-500/10 text-teal-300 border-teal-500/20',
      THREAT_FEED: 'bg-purple-500/10 text-purple-300 border-purple-500/20',
      MLOPS: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20',
      SECURITY: 'bg-rose-500/10 text-rose-300 border-rose-500/20'
    };
    return (
      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${colors[cat] || 'bg-slate-800 text-slate-300'}`}>
        {cat}
      </span>
    );
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                SOC Audit Trail & Governance Logs
                <span className="text-xs font-mono font-normal px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                  Immutable Trail
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Comprehensive activity log recording analyst investigations, policy changes, remediation rules, and auth events
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3">
          <button
            onClick={() => fetchLogs()}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-semibold transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={handleExportCsv}
            className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-4 backdrop-blur-sm flex flex-col md:flex-row gap-4 justify-between items-center">
        {/* Search */}
        <form onSubmit={handleSearch} className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search action, actor, target..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </form>

        {/* Category Pills */}
        <div className="flex flex-wrap gap-1.5 items-center">
          {['ALL', 'AUTH', 'CASE', 'REMEDIATION', 'CONFIG', 'THREAT_FEED', 'MLOPS'].map(cat => (
            <button
              key={cat}
              onClick={() => {
                setSelectedCategory(cat);
                setPage(0);
              }}
              className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors ${
                selectedCategory === cat
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Severity Selector */}
        <div className="flex items-center space-x-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={selectedSeverity}
            onChange={e => {
              setSelectedSeverity(e.target.value);
              setPage(0);
            }}
            className="bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="INFO">INFO Only</option>
            <option value="WARNING">WARNING Only</option>
            <option value="CRITICAL">CRITICAL Only</option>
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-sm shadow-xl">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center text-xs text-slate-400 font-mono">
          <span>Displaying {logs.length} of {total} total logged events</span>
          <span>Page {page + 1} of {Math.max(1, Math.ceil(total / limit))}</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Target</th>
                <th className="px-4 py-3">Details</th>
                <th className="px-4 py-3">IP Address</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-slate-500 font-mono">
                    No audit log records match the current filter criteria.
                  </td>
                </tr>
              ) : (
                logs.map(log => (
                  <tr key={log.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 text-slate-400 font-mono whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 font-semibold text-slate-200 flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5 text-slate-400" />
                      <span>{log.actor}</span>
                    </td>
                    <td className="px-4 py-3 font-mono font-bold text-cyan-300">
                      {log.action}
                    </td>
                    <td className="px-4 py-3">
                      {getCategoryBadge(log.category)}
                    </td>
                    <td className="px-4 py-3">
                      {getSeverityBadge(log.severity)}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300">
                      {log.target || '—'}
                    </td>
                    <td className="px-4 py-3 text-slate-300 max-w-xs truncate" title={log.details}>
                      {log.details}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400">
                      {log.ipAddress || '127.0.0.1'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="p-4 border-t border-slate-800 flex justify-between items-center text-xs">
          <button
            disabled={page === 0}
            onClick={() => setPage(prev => Math.max(0, prev - 1))}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:hover:bg-slate-800 font-semibold transition-colors"
          >
            Previous
          </button>
          <span className="text-slate-400 font-mono">
            Showing {(page * limit) + 1} – {Math.min(total, (page + 1) * limit)}
          </span>
          <button
            disabled={(page + 1) * limit >= total}
            onClick={() => setPage(prev => prev + 1)}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:hover:bg-slate-800 font-semibold transition-colors"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
};
