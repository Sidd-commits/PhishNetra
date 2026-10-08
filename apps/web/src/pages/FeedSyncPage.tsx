import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import { ThreatFeedStatus, ThreatFeedSyncResult, ThreatFeedSource } from '@phishnetra/shared';
import {
  Radio,
  RefreshCw,
  Globe,
  Database,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Shield,
  Zap,
  Layers,
  ArrowUpRight,
  Sparkles
} from 'lucide-react';

export const FeedSyncPage: React.FC = () => {
  const { showToast } = useToast();
  const [feeds, setFeeds] = useState<ThreatFeedStatus[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [syncingSource, setSyncingSource] = useState<string | null>(null);
  const [syncAllLoading, setSyncAllLoading] = useState<boolean>(false);
  const [recentSyncs, setRecentSyncs] = useState<ThreatFeedSyncResult[]>([]);

  useEffect(() => {
    fetchFeeds();
  }, []);

  const fetchFeeds = async () => {
    try {
      setLoading(true);
      const res = await api.listThreatFeeds();
      setFeeds(res);
    } catch (err: any) {
      showToast('error', 'Failed to load threat feeds', err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSyncFeed = async (source: ThreatFeedSource) => {
    try {
      setSyncingSource(source);
      const result = await api.syncThreatFeed(source);
      setRecentSyncs(prev => [result, ...prev.slice(0, 9)]);
      await fetchFeeds();
      showToast('success', `${source} Synced`, `Ingested ${result.newIocsAdded} new IOCs, ${result.duplicatesSkipped} duplicates skipped`);
    } catch (err: any) {
      showToast('error', `Sync failed for ${source}`, err.message);
    } finally {
      setSyncingSource(null);
    }
  };

  const handleSyncAll = async () => {
    try {
      setSyncAllLoading(true);
      const results = await api.syncAllThreatFeeds();
      setRecentSyncs(prev => [...results, ...prev.slice(0, 9)]);
      await fetchFeeds();
      const totalNew = results.reduce((acc, r) => acc + r.newIocsAdded, 0);
      showToast('success', 'All Feeds Synced', `Ingested ${totalNew} new malicious IOCs across active threat feeds`);
    } catch (err: any) {
      showToast('error', 'Feed synchronization failed', err.message);
    } finally {
      setSyncAllLoading(false);
    }
  };

  const handleToggleFeed = async (source: ThreatFeedSource, currentStatus: boolean) => {
    try {
      await api.toggleThreatFeed(source, !currentStatus);
      await fetchFeeds();
      showToast('info', 'Feed Status Updated', `${source} is now ${!currentStatus ? 'ENABLED' : 'DISABLED'}`);
    } catch (err: any) {
      showToast('error', 'Status update failed', err.message);
    }
  };

  const totalIocs = feeds.reduce((sum, f) => sum + f.iocCount, 0);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Radio className="w-6 h-6 animate-pulse text-cyan-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                Threat Intelligence Feed Subscriptions
                <span className="text-xs font-mono font-normal px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                  Live Sync
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Continuous ingestion of global malicious domains, IPs, and phishing IOCs into the Threat Graph
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3">
          <button
            onClick={() => fetchFeeds()}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-semibold transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={handleSyncAll}
            disabled={syncAllLoading}
            className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
          >
            <Zap className={`w-3.5 h-3.5 ${syncAllLoading ? 'animate-bounce' : ''}`} />
            <span>{syncAllLoading ? 'Syncing Feeds...' : 'Sync All Feeds'}</span>
          </button>
        </div>
      </div>

      {/* Aggregate Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Total Ingested IOCs</span>
            <Database className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {totalIocs.toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-500">Cached IOCs across all active subscription feeds</p>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Active Threat Sources</span>
            <Globe className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {feeds.filter(f => f.enabled).length} / {feeds.length}
          </div>
          <p className="text-[11px] text-slate-500">URLhaus, OpenPhish, PhishTank feeds connected</p>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Automated Ingestion Cycle</span>
            <Clock className="w-4 h-4 text-teal-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            Every 60 min
          </div>
          <p className="text-[11px] text-slate-500">Background cron scheduler syncing active feeds</p>
        </div>
      </div>

      {/* Feed Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {feeds.map(feed => {
          const isSyncing = syncingSource === feed.source;
          return (
            <div
              key={feed.id}
              className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm shadow-xl flex flex-col justify-between space-y-6"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                      {feed.source}
                    </span>
                    <h3 className="text-base font-bold text-white mt-1">{feed.name}</h3>
                  </div>
                  <button
                    onClick={() => handleToggleFeed(feed.source, feed.enabled)}
                    className={`w-11 h-6 rounded-full transition-colors relative p-0.5 ${
                      feed.enabled ? 'bg-cyan-500' : 'bg-slate-800'
                    }`}
                  >
                    <div
                      className={`w-5 h-5 rounded-full bg-slate-950 transition-transform ${
                        feed.enabled ? 'translate-x-5' : 'translate-x-0'
                      }`}
                    />
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-3 pt-2">
                  <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 uppercase font-mono">IOC Volume</span>
                    <p className="text-base font-bold font-mono text-white mt-0.5">
                      {feed.iocCount.toLocaleString()}
                    </p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 uppercase font-mono">Last Synchronized</span>
                    <p className="text-xs font-mono text-slate-300 mt-1">
                      {feed.lastSyncAt ? new Date(feed.lastSyncAt).toLocaleTimeString() : 'Never'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Card Footer Actions */}
              <div className="flex items-center justify-between pt-4 border-t border-slate-800">
                <div className="flex items-center space-x-1.5 text-xs">
                  {feed.lastSyncStatus === 'SUCCESS' ? (
                    <span className="flex items-center space-x-1 text-emerald-400 font-mono text-[11px]">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>HEALTHY</span>
                    </span>
                  ) : (
                    <span className="flex items-center space-x-1 text-slate-500 font-mono text-[11px]">
                      <Clock className="w-3.5 h-3.5" />
                      <span>STANDBY</span>
                    </span>
                  )}
                </div>

                <button
                  disabled={isSyncing || !feed.enabled}
                  onClick={() => handleSyncFeed(feed.source)}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/20 text-xs font-semibold transition-colors disabled:opacity-40"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
                  <span>{isSyncing ? 'Syncing...' : 'Sync Now'}</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Live Sync History */}
      {recentSyncs.length > 0 && (
        <div className="bg-slate-900/70 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-sm shadow-xl">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              Recent Feed Synchronization History
            </h4>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Feed Source</th>
                  <th className="px-4 py-3">Duration</th>
                  <th className="px-4 py-3">Total Processed</th>
                  <th className="px-4 py-3">New IOCs Added</th>
                  <th className="px-4 py-3">Deduplicated</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {recentSyncs.map((sync, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono font-bold text-cyan-300">{sync.source}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{sync.syncDurationMs}ms</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{sync.totalFetched}</td>
                    <td className="px-4 py-3 font-mono text-emerald-400 font-bold">+{sync.newIocsAdded}</td>
                    <td className="px-4 py-3 font-mono text-slate-400">{sync.duplicatesSkipped}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {sync.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400">
                      {new Date(sync.syncedAt).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
