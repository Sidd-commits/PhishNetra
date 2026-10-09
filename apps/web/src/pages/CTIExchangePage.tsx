import React, { useState, useEffect } from 'react';
import {
  Radio,
  RefreshCw,
  Plus,
  Shield,
  Layers,
  Database,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Filter,
  Activity
} from 'lucide-react';
import { api } from '../services/api';
import { TAXIIFeedConfig, CTIIndicator, CTIExchangeStats, TAXIISyncResult } from '@phishnetra/shared';

export const CTIExchangePage: React.FC = () => {
  const [feeds, setFeeds] = useState<TAXIIFeedConfig[]>([]);
  const [indicators, setIndicators] = useState<CTIIndicator[]>([]);
  const [stats, setStats] = useState<CTIExchangeStats | null>(null);
  const [syncHistory, setSyncHistory] = useState<TAXIISyncResult[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [syncingFeedId, setSyncingFeedId] = useState<string | null>(null);
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedTlp, setSelectedTlp] = useState<string>('ALL');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // New Feed Form State
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [newFeedName, setNewFeedName] = useState<string>('');
  const [newFeedApiRoot, setNewFeedApiRoot] = useState<string>('https://taxii.example-threat-intel.org/taxii2/');
  const [newFeedCollection, setNewFeedCollection] = useState<string>('community-phishing-indicators');
  const [newFeedTlp, setNewFeedTlp] = useState<'TLP:WHITE' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED'>('TLP:GREEN');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [fetchedFeeds, fetchedIndicators, fetchedStats] = await Promise.all([
        api.listCTIFeeds(),
        api.listCTIIndicators({ limit: 50 }),
        api.getCTIExchangeStats()
      ]);
      setFeeds(fetchedFeeds);
      setIndicators(fetchedIndicators);
      setStats(fetchedStats);
    } catch (err: any) {
      console.error('Failed to load CTI Exchange data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSyncFeed = async (feedId: string) => {
    try {
      setSyncingFeedId(feedId);
      const result = await api.syncCTIFeed(feedId);
      setSyncHistory(prev => [result, ...prev]);
      setToastMessage(`Successfully synced ${result.indicatorsIngested} STIX 2.1 indicators from ${result.feedName}`);
      setTimeout(() => setToastMessage(null), 4000);
      await loadData();
    } catch (err: any) {
      console.error('Failed to sync TAXII feed:', err);
    } finally {
      setSyncingFeedId(null);
    }
  };

  const handleAddFeed = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newFeedName.trim()) return;

    try {
      await api.createCTIFeed({
        name: newFeedName,
        description: 'Custom verified threat intelligence channel',
        apiRootUrl: newFeedApiRoot,
        collectionId: newFeedCollection,
        authType: 'API_KEY',
        apiKey: 'demo-api-key',
        tlpMarking: newFeedTlp,
        syncIntervalMinutes: 60,
        isActive: true,
        autoBlockIndicators: true
      });
      setShowAddModal(false);
      setNewFeedName('');
      setToastMessage('New TAXII 2.1 feed registered successfully');
      setTimeout(() => setToastMessage(null), 4000);
      await loadData();
    } catch (err: any) {
      console.error('Failed to add feed:', err);
    }
  };

  const filteredIndicators = indicators.filter(ind => {
    if (selectedType !== 'ALL' && ind.indicatorType !== selectedType) return false;
    if (selectedTlp !== 'ALL' && ind.tlp !== selectedTlp) return false;
    return true;
  });

  const getTlpColor = (tlp: string) => {
    switch (tlp) {
      case 'TLP:RED': return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'TLP:AMBER':
      case 'TLP:AMBER+STRICT': return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'TLP:GREEN': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'TLP:WHITE': default: return 'bg-slate-500/10 text-slate-300 border-slate-500/30';
    }
  };

  return (
    <div className="min-w-0 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center space-x-2 bg-emerald-950/90 text-emerald-300 border border-emerald-500/40 px-4 py-3 rounded-xl shadow-2xl backdrop-blur-md animate-in fade-in slide-in-from-bottom-2">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          <span className="text-xs font-semibold">{toastMessage}</span>
        </div>
      )}

      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950/50 to-slate-900 border border-slate-800 p-6 sm:p-8">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center space-x-2.5">
              <span className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
                <Radio className="w-5 h-5 animate-pulse" />
              </span>
              <span className="text-xs font-mono font-semibold tracking-wider text-indigo-400 uppercase">
                Milestone 20 • Autonomous Threat Exchange
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Decentralized CTI & TAXII 2.1 Threat Exchange
            </h1>
            <p className="text-sm text-slate-400 max-w-2xl">
              Bidirectional ingestion and dissemination of OASIS STIX 2.1 indicator bundles across CISA AIS,
              AlienVault OTX, and sector ISACs with automated confidence scoring and edge blocking.
            </p>
          </div>

          <div className="flex items-center space-x-3 shrink-0">
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-lg shadow-indigo-600/30 transition-all hover:scale-105"
            >
              <Plus className="w-4 h-4" />
              <span>Connect TAXII Feed</span>
            </button>
            <button
              onClick={loadData}
              disabled={loading}
              className="flex items-center space-x-1.5 px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">Refresh</span>
            </button>
          </div>
        </div>

        {/* Telemetry Stats Bar */}
        {stats && (
          <div className="mt-8 grid grid-cols-2 sm:grid-cols-4 gap-4 border-t border-slate-800/80 pt-6">
            <div className="space-y-1">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Active TAXII Feeds</div>
              <div className="text-2xl font-black text-white font-mono">{stats.activeFeeds} / {stats.totalFeeds}</div>
            </div>
            <div className="space-y-1">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Ingested IOCs</div>
              <div className="text-2xl font-black text-indigo-400 font-mono">{stats.totalIndicators}</div>
            </div>
            <div className="space-y-1">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Domains & URLs</div>
              <div className="text-2xl font-black text-cyan-400 font-mono">
                {(stats.indicatorsByType['DOMAIN'] || 0) + (stats.indicatorsByType['URL'] || 0)}
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Defense Dispatch</div>
              <div className="text-xs font-semibold text-emerald-400 flex items-center space-x-1 mt-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Auto-Blocking Active</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Connected Feeds Cards */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-white flex items-center space-x-2">
            <Database className="w-4 h-4 text-indigo-400" />
            <span>Configured TAXII 2.1 Ingestion Channels</span>
          </h2>
          <span className="text-xs text-slate-400 font-mono">{feeds.length} Channels Online</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {feeds.map(feed => (
            <div
              key={feed.id}
              className="rounded-xl bg-slate-900/90 border border-slate-800 p-5 flex flex-col justify-between space-y-4 hover:border-indigo-500/40 transition-colors"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <h3 className="text-sm font-bold text-white tracking-tight">{feed.name}</h3>
                  <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full border ${getTlpColor(feed.tlpMarking)}`}>
                    {feed.tlpMarking}
                  </span>
                </div>
                <p className="text-xs text-slate-400 line-clamp-2">{feed.description}</p>
                <div className="text-[11px] font-mono text-slate-500 truncate" title={feed.apiRootUrl}>
                  Root: {feed.apiRootUrl}
                </div>
              </div>

              <div className="border-t border-slate-800/80 pt-4 flex items-center justify-between">
                <div className="space-y-0.5">
                  <div className="text-[10px] font-mono text-slate-500 uppercase">Ingested</div>
                  <div className="text-xs font-bold text-slate-200 font-mono">{feed.totalIndicatorsIngested} STIX IOCs</div>
                </div>

                <button
                  onClick={() => handleSyncFeed(feed.id)}
                  disabled={syncingFeedId === feed.id}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-xs font-semibold transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={`w-3 h-3 ${syncingFeedId === feed.id ? 'animate-spin' : ''}`} />
                  <span>{syncingFeedId === feed.id ? 'Syncing...' : 'Sync Now'}</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Filter and Indicators Table */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h2 className="text-base font-bold text-white">Ingested CTI Threat Indicators</h2>
            <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded-md">
              {filteredIndicators.length}
            </span>
          </div>

          <div className="flex items-center space-x-2">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            {/* Type Filter */}
            <select
              value={selectedType}
              onChange={e => setSelectedType(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Types</option>
              <option value="URL">URLs</option>
              <option value="DOMAIN">Domains</option>
              <option value="IPV4">IPv4 Addresses</option>
            </select>

            {/* TLP Filter */}
            <select
              value={selectedTlp}
              onChange={e => setSelectedTlp(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All TLP</option>
              <option value="TLP:WHITE">TLP:WHITE</option>
              <option value="TLP:GREEN">TLP:GREEN</option>
              <option value="TLP:AMBER">TLP:AMBER</option>
              <option value="TLP:RED">TLP:RED</option>
            </select>
          </div>
        </div>

        {/* Indicators Table */}
        <div className="overflow-hidden rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                <tr>
                  <th className="px-4 py-3">Indicator Value</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Source Channel</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">TLP</th>
                  <th className="px-4 py-3 text-right">STIX ID</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredIndicators.map(ind => (
                  <tr key={ind.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 font-semibold text-slate-200">
                      <div className="flex items-center space-x-2">
                        <span className="truncate max-w-xs sm:max-w-md">{ind.indicatorValue}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                        {ind.indicatorType}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-sans truncate max-w-[200px]">
                      {ind.sourceFeedName}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center space-x-2">
                        <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-full ${ind.confidence >= 90 ? 'bg-rose-500' : 'bg-amber-500'}`}
                            style={{ width: `${ind.confidence}%` }}
                          />
                        </div>
                        <span className="text-[11px] text-slate-300 font-bold">{ind.confidence}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getTlpColor(ind.tlp)}`}>
                        {ind.tlp}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right text-slate-500 text-[10px] truncate max-w-[140px]">
                      {ind.stixId}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Add Feed Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-2xl bg-slate-900 border border-slate-800 p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center space-x-2">
              <Plus className="w-5 h-5 text-indigo-400" />
              <span>Connect TAXII 2.1 Endpoint</span>
            </h3>
            <p className="text-xs text-slate-400">
              Register an external STIX/TAXII 2.1 discovery root to continuously stream bidirectional threat indicators.
            </p>

            <form onSubmit={handleAddFeed} className="space-y-4 text-xs">
              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Feed Display Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. NATO Cyber Defense TAXII Feed"
                  value={newFeedName}
                  onChange={e => setNewFeedName(e.target.value)}
                  className="w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">API Root URL</label>
                <input
                  type="url"
                  required
                  value={newFeedApiRoot}
                  onChange={e => setNewFeedApiRoot(e.target.value)}
                  className="w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Collection Identifier</label>
                <input
                  type="text"
                  required
                  value={newFeedCollection}
                  onChange={e => setNewFeedCollection(e.target.value)}
                  className="w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">TLP Classification</label>
                <select
                  value={newFeedTlp}
                  onChange={e => setNewFeedTlp(e.target.value as any)}
                  className="w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-white focus:outline-none focus:border-indigo-500"
                >
                  <option value="TLP:WHITE">TLP:WHITE</option>
                  <option value="TLP:GREEN">TLP:GREEN</option>
                  <option value="TLP:AMBER">TLP:AMBER</option>
                  <option value="TLP:RED">TLP:RED</option>
                </select>
              </div>

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold transition-colors"
                >
                  Confirm Connection
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
export default CTIExchangePage;
