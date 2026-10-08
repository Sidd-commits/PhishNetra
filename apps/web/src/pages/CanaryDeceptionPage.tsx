import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
  CanaryToken,
  CanaryTriggerEvent,
  CanaryTokenType,
  EvidenceSeverity
} from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  Sparkles,
  ShieldAlert,
  Flame,
  Zap,
  Plus,
  Copy,
  Check,
  Radio,
  Eye,
  Terminal,
  Activity,
  Globe,
  Clock,
  Key,
  Code,
  FileCode,
  AlertTriangle,
  RefreshCw,
  Power
} from 'lucide-react';

export const CanaryDeceptionPage: React.FC = () => {
  const { showToast } = useToast();

  const [tokens, setTokens] = useState<CanaryToken[]>([]);
  const [triggers, setTriggers] = useState<CanaryTriggerEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'TOKENS' | 'TRIGGERS'>('TOKENS');
  const [showModal, setShowModal] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // New Canary Form
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState<CanaryTokenType>('HTTP_WEB_BUG');
  const [newLocation, setNewLocation] = useState('');
  const [newSeverity, setNewSeverity] = useState<EvidenceSeverity>('HIGH');
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [tList, trList] = await Promise.all([
        api.listCanaryTokens(),
        api.listCanaryTriggers()
      ]);
      setTokens(tList);
      setTriggers(trList);
    } catch (err: any) {
      showToast('error', 'Load Failed', err.response?.data?.error || 'Failed to load canary deception data');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newLocation.trim()) {
      showToast('warning', 'Incomplete Form', 'Please fill all required canary fields');
      return;
    }

    setCreating(true);
    try {
      const created = await api.createCanaryToken({
        name: newName,
        tokenType: newType,
        targetDeployLocation: newLocation,
        alertSeverity: newSeverity
      });
      setTokens(prev => [created, ...prev]);
      setShowModal(false);
      setNewName('');
      setNewLocation('');
      showToast('success', 'Canary Deployed', `Canary tripwire "${created.name}" deployed successfully`);
    } catch (err: any) {
      showToast('error', 'Deploy Failed', err.response?.data?.error || 'Failed to create canary token');
    } finally {
      setCreating(false);
    }
  };

  const handleToggleStatus = async (token: CanaryToken) => {
    const nextStatus = token.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE';
    try {
      const updated = await api.toggleCanaryTokenStatus(token.id, nextStatus);
      setTokens(prev => prev.map(t => (t.id === updated.id ? updated : t)));
      showToast('info', 'Status Updated', `Canary "${token.name}" is now ${nextStatus}`);
    } catch (err: any) {
      showToast('error', 'Update Failed', 'Failed to toggle canary status');
    }
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast('success', 'Copied to Clipboard', 'Deploy snippet copied to clipboard');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const totalTriggersCount = tokens.reduce((acc, t) => acc + t.triggeredCount, 0);

  return (
    <div className="space-y-6 animate-in fade-in duration-500 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-400 shadow-lg shadow-amber-500/10">
              <Eye className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-2xl font-black tracking-tight text-white">Canary Deception Engine</h1>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/20">
                  Active Defense Tripwires
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Deploy honeypot canaries, fake credentials, and anti-cloning web bugs to trap phishing actors in real time
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={loadData}
            className="p-2 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 transition-colors"
            title="Refresh Deception Telemetry"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-amber-500 to-rose-600 hover:from-amber-400 hover:to-rose-500 text-slate-950 font-bold text-xs shadow-lg shadow-amber-500/20 transition-all flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>Deploy Canary Token</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-4 backdrop-blur-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Active Canaries</span>
            <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
          </div>
          <div className="text-2xl font-black text-white mt-2">
            {tokens.filter(t => t.status === 'ACTIVE').length} / {tokens.length}
          </div>
          <div className="text-[11px] text-emerald-400 mt-1">Live tripwires armed</div>
        </div>

        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-4 backdrop-blur-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Tripwire Hits</span>
            <Flame className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-black text-rose-400 mt-2">
            {totalTriggersCount}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Across web & DNS beacons</div>
        </div>

        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-4 backdrop-blur-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Captured Forensics</span>
            <Terminal className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-cyan-400 mt-2">
            {triggers.length}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">JA3 & header logs captured</div>
        </div>

        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-4 backdrop-blur-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Deception Coverage</span>
            <Zap className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-black text-indigo-400 mt-2">
            99.8%
          </div>
          <div className="text-[11px] text-indigo-300 mt-1">Anti-scraping defense active</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-800">
        <button
          onClick={() => setActiveTab('TOKENS')}
          className={`px-4 py-2.5 text-xs font-bold transition-colors border-b-2 flex items-center space-x-2 ${
            activeTab === 'TOKENS'
              ? 'border-amber-400 text-amber-300'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Key className="w-3.5 h-3.5" />
          <span>Canary Tokens ({tokens.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('TRIGGERS')}
          className={`px-4 py-2.5 text-xs font-bold transition-colors border-b-2 flex items-center space-x-2 ${
            activeTab === 'TRIGGERS'
              ? 'border-rose-400 text-rose-300'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Flame className="w-3.5 h-3.5" />
          <span>Recorded Attacker Triggers ({triggers.length})</span>
        </button>
      </div>

      {/* Tab Content: Tokens */}
      {activeTab === 'TOKENS' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {tokens.map(token => (
            <div
              key={token.id}
              className={`rounded-2xl border p-5 backdrop-blur-xl transition-all ${
                token.status === 'ACTIVE'
                  ? 'bg-slate-900/70 border-slate-800 hover:border-amber-500/40'
                  : 'bg-slate-950/50 border-slate-900 opacity-60'
              }`}
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-sm font-bold text-white">{token.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold ${
                        token.status === 'ACTIVE'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {token.status}
                    </span>
                  </div>
                  <div className="flex items-center space-x-3 text-[11px] text-slate-400 mt-1">
                    <span className="text-cyan-400 font-mono font-semibold">{token.tokenType}</span>
                    <span>•</span>
                    <span>Deploy Target: <strong className="text-slate-300">{token.targetDeployLocation}</strong></span>
                  </div>
                </div>

                <button
                  onClick={() => handleToggleStatus(token)}
                  title={`Toggle ${token.status === 'ACTIVE' ? 'Disabled' : 'Active'}`}
                  className={`p-2 rounded-xl border transition-colors ${
                    token.status === 'ACTIVE'
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  <Power className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Code Snippet Box */}
              <div className="mt-4 rounded-xl bg-slate-950 border border-slate-800/80 p-3 font-mono text-[11px]">
                <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1.5">
                  <span className="flex items-center space-x-1">
                    <Code className="w-3 h-3 text-amber-400" />
                    <span>Deployable Honeypot Snippet</span>
                  </span>
                  <button
                    onClick={() => handleCopy(token.deploySnippet, token.id)}
                    className="text-amber-400 hover:text-amber-300 flex items-center space-x-1"
                  >
                    {copiedKey === token.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === token.id ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="text-slate-300 overflow-x-auto whitespace-pre-wrap">{token.deploySnippet}</pre>
              </div>

              {/* Footer info */}
              <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
                <span className="flex items-center space-x-1">
                  <Flame className="w-3 h-3 text-rose-400" />
                  <span>Triggers: <strong className="text-white">{token.triggeredCount}</strong></span>
                </span>
                <span>Last Fired: {token.lastTriggeredAt ? new Date(token.lastTriggeredAt).toLocaleString() : 'Never'}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab Content: Triggers */}
      {activeTab === 'TRIGGERS' && (
        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Canary Token</th>
                  <th className="py-3 px-4">Attacker IP & Geo</th>
                  <th className="py-3 px-4">User-Agent & JA3 Signature</th>
                  <th className="py-3 px-4">Captured Attacker Intent</th>
                  <th className="py-3 px-4">Triggered At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {triggers.map(trig => (
                  <tr key={trig.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3.5 px-4">
                      <div className="font-bold text-white font-sans">{trig.tokenName}</div>
                      <div className="text-[10px] text-cyan-400">{trig.tokenType}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="text-rose-400 font-bold">{trig.sourceIp}</div>
                      <div className="text-[10px] text-slate-400">{trig.city}, {trig.country}</div>
                    </td>
                    <td className="py-3.5 px-4 max-w-xs truncate">
                      <div className="text-slate-300 truncate" title={trig.userAgent}>{trig.userAgent}</div>
                      <div className="text-[10px] text-indigo-400 truncate" title={trig.ja3Fingerprint}>
                        JA3: {trig.ja3Fingerprint ? trig.ja3Fingerprint.slice(0, 32) + '...' : 'N/A'}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-sans">
                      <div className="text-slate-200 text-[11px]">{trig.attackerIntent}</div>
                      {trig.capturedPayload && (
                        <div className="text-[9px] font-mono text-amber-300 mt-0.5 truncate max-w-xs" title={trig.capturedPayload}>
                          Payload: {trig.capturedPayload}
                        </div>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                      {new Date(trig.triggeredAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Deploy Canary Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-800 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Eye className="w-5 h-5 text-amber-400" />
                <h2 className="text-lg font-bold text-white">Deploy Deception Tripwire</h2>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateToken} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Canary Token Name</label>
                <input
                  type="text"
                  value={newName}
                  onChange={e => setNewName(e.target.value)}
                  placeholder="e.g., Decoy AWS Admin Credentials"
                  required
                  className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-amber-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Token Type</label>
                  <select
                    value={newType}
                    onChange={e => setNewType(e.target.value as CanaryTokenType)}
                    className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-cyan-300 focus:outline-none"
                  >
                    <option value="HTTP_WEB_BUG">HTTP Web Bug</option>
                    <option value="DNS_TRIPWIRE">DNS Tripwire</option>
                    <option value="DECOY_CREDENTIAL">Decoy Credential</option>
                    <option value="CLONED_LOGIN_BEACON">Cloned Page Beacon</option>
                    <option value="FAKE_API_KEY">Fake API Key</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Alert Severity</label>
                  <select
                    value={newSeverity}
                    onChange={e => setNewSeverity(e.target.value as EvidenceSeverity)}
                    className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-rose-300 focus:outline-none"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Deployment Location</label>
                <input
                  type="text"
                  value={newLocation}
                  onChange={e => setNewLocation(e.target.value)}
                  placeholder="e.g., https://login.corp.com/index.html or staging-repo"
                  required
                  className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-amber-400"
                />
              </div>

              <div className="pt-3 border-t border-slate-800 flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-5 py-2 rounded-xl bg-amber-400 hover:bg-amber-300 text-slate-950 font-bold text-xs shadow-lg shadow-amber-500/20"
                >
                  {creating ? 'Deploying...' : 'Deploy Canary'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
