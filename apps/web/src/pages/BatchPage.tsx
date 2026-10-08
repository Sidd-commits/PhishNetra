import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { BatchJobResponse, BatchItemResult } from '@phishnetra/shared';
import {
  Layers,
  Play,
  FileText,
  Upload,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  Download,
  RotateCcw,
  Ban,
  ExternalLink,
  ChevronRight,
  Activity
} from 'lucide-react';

export const BatchPage: React.FC = () => {
  const navigate = useNavigate();
  const [urlInput, setUrlInput] = useState('');
  const [includePageAnalysis, setIncludePageAnalysis] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [activeJob, setActiveJob] = useState<BatchJobResponse | null>(null);
  const [recentJobs, setRecentJobs] = useState<BatchJobResponse[]>([]);
  const [polling, setPolling] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load recent jobs on mount
  useEffect(() => {
    loadRecentJobs();
  }, []);

  // Poll active job until COMPLETED or FAILED or CANCELLED
  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;

    if (activeJob && (activeJob.status === 'QUEUED' || activeJob.status === 'RUNNING')) {
      setPolling(true);
      timer = setInterval(async () => {
        try {
          const updated = await api.getBatchJob(activeJob.id);
          setActiveJob(updated);
          if (updated.status !== 'QUEUED' && updated.status !== 'RUNNING') {
            setPolling(false);
            loadRecentJobs();
          }
        } catch (err: any) {
          console.error('Polling error:', err);
        }
      }, 1500);
    } else {
      setPolling(false);
    }

    return () => {
      if (timer) clearInterval(timer);
    };
  }, [activeJob?.id, activeJob?.status]);

  const loadRecentJobs = async () => {
    try {
      const res = await api.listBatchJobs(10, 0);
      setRecentJobs(res.jobs);
    } catch (err: any) {
      console.warn('Failed to load recent batch jobs:', err.message);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const urls = urlInput
      .split(/[\r\n,;]+/)
      .map((u) => u.trim())
      .filter((u) => u.length > 0 && !u.startsWith('#') && u.toLowerCase() !== 'url');

    if (urls.length === 0) {
      setError('Please provide at least one valid URL to analyze.');
      return;
    }

    try {
      setIsSubmitting(true);
      const res = await api.createBatchJob({
        urls,
        includePageAnalysis
      });
      setActiveJob(res);
      setUrlInput('');
      loadRecentJobs();
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Failed to submit batch job.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setUrlInput(content);
      }
    };
    reader.readAsText(file);
  };

  const handleCancel = async () => {
    if (!activeJob) return;
    try {
      await api.cancelBatchJob(activeJob.id);
      const updated = await api.getBatchJob(activeJob.id);
      setActiveJob(updated);
      loadRecentJobs();
    } catch (err: any) {
      console.error('Cancel error:', err);
    }
  };

  const selectJob = async (jobId: string) => {
    try {
      const job = await api.getBatchJob(jobId);
      setActiveJob(job);
    } catch (err: any) {
      console.error('Fetch job error:', err);
    }
  };

  const getVerdictBadge = (verdict?: string | null) => {
    switch (verdict) {
      case 'PHISHING':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">PHISHING</span>;
      case 'SUSPICIOUS':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">SUSPICIOUS</span>;
      case 'SAFE':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">SAFE</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-400 border border-slate-700">PENDING</span>;
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Layers className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">High-Throughput Batch Scanner</h1>
              <p className="text-sm text-slate-400">
                Asynchronous multi-URL queue processing with persistent caching & multi-layer threat assessment.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center space-x-2 px-3.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 rounded-lg text-xs font-medium transition-colors"
          >
            <Upload className="w-4 h-4 text-cyan-400" />
            <span>Upload CSV/TXT</span>
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv,.txt,.json"
            onChange={handleFileUpload}
            className="hidden"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Form & History */}
        <div className="lg:col-span-1 space-y-6">
          {/* Submission Form */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>Queue URL Batch</span>
            </h2>

            {error && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs text-rose-300 flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">
                  Target URLs (one per line, comma, or paste CSV):
                </label>
                <textarea
                  rows={6}
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder={`https://example-phish-login.com\nhttps://secure-bank-auth.com\nhttps://legitimate-service.org`}
                  className="w-full bg-slate-950/80 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none transition-all resize-y"
                  disabled={isSubmitting}
                />
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="includePageAnalysis"
                  checked={includePageAnalysis}
                  onChange={(e) => setIncludePageAnalysis(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-400"
                />
                <label htmlFor="includePageAnalysis" className="text-xs text-slate-300 select-none cursor-pointer">
                  Include Deep DOM & Brand Inspection
                </label>
              </div>

              <button
                type="submit"
                disabled={isSubmitting || !urlInput.trim()}
                className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-medium text-xs rounded-lg shadow-md shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {isSubmitting ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin" />
                    <span>Enqueuing Batch...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    <span>Start Async Batch Scan</span>
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Recent Batch Scans List */}
          <div className="bg-slate-900/40 border border-slate-800/80 rounded-xl p-5 shadow-lg space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between">
              <span>Recent Batch Jobs</span>
              <button onClick={loadRecentJobs} className="text-slate-500 hover:text-cyan-400">
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </h3>

            {recentJobs.length === 0 ? (
              <p className="text-xs text-slate-500 py-3 text-center">No previous batch scans recorded.</p>
            ) : (
              <div className="space-y-2">
                {recentJobs.map((job) => (
                  <button
                    key={job.id}
                    onClick={() => selectJob(job.id)}
                    className={`w-full text-left p-3 rounded-lg border text-xs transition-all flex items-center justify-between ${
                      activeJob?.id === job.id
                        ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-300'
                        : 'bg-slate-950/60 border-slate-800 text-slate-300 hover:bg-slate-800/50'
                    }`}
                  >
                    <div>
                      <div className="font-mono font-medium truncate max-w-[170px]">
                        Job {job.id.slice(0, 8)}...
                      </div>
                      <div className="text-[11px] text-slate-500">
                        {job.totalUrls} URLs • {new Date(job.createdAt).toLocaleTimeString()}
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-1.5 py-0.5 text-[10px] rounded font-semibold ${
                        job.status === 'COMPLETED' ? 'bg-emerald-500/20 text-emerald-300' :
                        job.status === 'RUNNING' ? 'bg-cyan-500/20 text-cyan-300 animate-pulse' :
                        job.status === 'CANCELLED' ? 'bg-slate-800 text-slate-400' :
                        'bg-amber-500/20 text-amber-300'
                      }`}>
                        {job.status}
                      </span>
                      <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Active Batch Details & Items Table */}
        <div className="lg:col-span-2 space-y-6">
          {activeJob ? (
            <div className="space-y-6">
              {/* Batch Status & Progress Banner */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/60 pb-4">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-mono text-cyan-400">BATCH JOB</span>
                      <span className="text-xs font-mono text-slate-400">{activeJob.id}</span>
                      {polling && (
                        <span className="flex items-center space-x-1 text-[11px] text-cyan-400 font-mono animate-pulse">
                          <Activity className="w-3 h-3" />
                          <span>Processing</span>
                        </span>
                      )}
                    </div>
                    <div className="text-lg font-bold text-white mt-0.5">
                      Status: <span className="text-cyan-400">{activeJob.status}</span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    {(activeJob.status === 'QUEUED' || activeJob.status === 'RUNNING') && (
                      <button
                        onClick={handleCancel}
                        className="flex items-center space-x-1 px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/30 rounded-lg text-xs font-medium transition-colors"
                      >
                        <Ban className="w-3.5 h-3.5" />
                        <span>Cancel</span>
                      </button>
                    )}

                    <a
                      href={api.getBatchExportUrl(activeJob.id, 'csv')}
                      className="flex items-center space-x-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium transition-colors"
                      download
                    >
                      <Download className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Export CSV</span>
                    </a>
                  </div>
                </div>

                {/* Animated Progress Bar */}
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs text-slate-400">
                    <span>Progress ({activeJob.processedUrls} of {activeJob.totalUrls} processed)</span>
                    <span className="font-mono text-cyan-400 font-semibold">{activeJob.progressPercent}%</span>
                  </div>
                  <div className="w-full bg-slate-950 rounded-full h-2.5 overflow-hidden border border-slate-800">
                    <div
                      className="bg-gradient-to-r from-cyan-500 to-indigo-500 h-full transition-all duration-300 ease-out"
                      style={{ width: `${activeJob.progressPercent}%` }}
                    />
                  </div>
                </div>

                {/* Stat Counters */}
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-2">
                  <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800/80 text-center">
                    <div className="text-[10px] text-slate-400 uppercase font-semibold">Total</div>
                    <div className="text-lg font-bold text-white font-mono mt-0.5">{activeJob.totalUrls}</div>
                  </div>
                  <div className="bg-emerald-950/20 p-3 rounded-lg border border-emerald-900/30 text-center">
                    <div className="text-[10px] text-emerald-400 uppercase font-semibold">Safe</div>
                    <div className="text-lg font-bold text-emerald-400 font-mono mt-0.5">{activeJob.safeCount}</div>
                  </div>
                  <div className="bg-amber-950/20 p-3 rounded-lg border border-amber-900/30 text-center">
                    <div className="text-[10px] text-amber-400 uppercase font-semibold">Suspicious</div>
                    <div className="text-lg font-bold text-amber-400 font-mono mt-0.5">{activeJob.suspiciousCount}</div>
                  </div>
                  <div className="bg-rose-950/20 p-3 rounded-lg border border-rose-900/30 text-center">
                    <div className="text-[10px] text-rose-400 uppercase font-semibold">Phishing</div>
                    <div className="text-lg font-bold text-rose-400 font-mono mt-0.5">{activeJob.phishingCount}</div>
                  </div>
                  <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800/80 text-center col-span-2 sm:col-span-1">
                    <div className="text-[10px] text-slate-400 uppercase font-semibold">Avg Risk</div>
                    <div className="text-lg font-bold text-cyan-400 font-mono mt-0.5">{activeJob.avgRiskScore}</div>
                  </div>
                </div>
              </div>

              {/* Items Table */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
                <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Processed Batch Items ({activeJob.items?.length || 0})
                  </h3>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/60 text-slate-400 uppercase text-[10px] font-semibold border-b border-slate-800">
                      <tr>
                        <th className="py-3 px-4">Target URL</th>
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Verdict</th>
                        <th className="py-3 px-4">Risk Score</th>
                        <th className="py-3 px-4 text-right">Investigation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {activeJob.items && activeJob.items.length > 0 ? (
                        activeJob.items.map((item: BatchItemResult) => (
                          <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                            <td className="py-3 px-4 max-w-[280px] truncate text-slate-200" title={item.url}>
                              {item.url}
                            </td>
                            <td className="py-3 px-4">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                                item.status === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400' :
                                item.status === 'RUNNING' ? 'bg-cyan-500/10 text-cyan-400 animate-pulse' :
                                item.status === 'FAILED' ? 'bg-rose-500/10 text-rose-400' :
                                'bg-slate-800 text-slate-400'
                              }`}>
                                {item.status}
                              </span>
                            </td>
                            <td className="py-3 px-4">
                              {getVerdictBadge(item.verdict)}
                            </td>
                            <td className="py-3 px-4">
                              {typeof item.riskScore === 'number' ? (
                                <span className={`font-bold ${
                                  item.riskScore >= 60 ? 'text-rose-400' :
                                  item.riskScore >= 30 ? 'text-amber-400' :
                                  'text-emerald-400'
                                }`}>
                                  {item.riskScore.toFixed(1)}
                                </span>
                              ) : (
                                <span className="text-slate-600">—</span>
                              )}
                            </td>
                            <td className="py-3 px-4 text-right">
                              {item.analysisId ? (
                                <button
                                  onClick={() => navigate(`/analysis/${item.analysisId}`)}
                                  className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 hover:underline font-sans text-xs"
                                >
                                  <span>View Report</span>
                                  <ExternalLink className="w-3 h-3" />
                                </button>
                              ) : (
                                <span className="text-slate-600 font-sans text-xs">Queued</span>
                              )}
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={5} className="py-6 text-center text-slate-500">
                            No items found in this batch job.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900/40 border border-slate-800/80 rounded-xl p-12 text-center space-y-4">
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 mx-auto flex items-center justify-center">
                <Layers className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-white">No Batch Job Selected</h3>
                <p className="text-xs text-slate-400 max-w-sm mx-auto mt-1">
                  Queue a list of URLs on the left or select a previous batch scan from history to inspect real-time progress and findings.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
