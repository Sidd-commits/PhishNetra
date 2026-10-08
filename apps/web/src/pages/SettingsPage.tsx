import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import {
  SystemConfig,
  ApiKeyItem,
  CreateApiKeyResponse
} from '@phishnetra/shared';
import {
  Sliders,
  Shield,
  Key,
  RotateCcw,
  Save,
  Plus,
  Trash2,
  Copy,
  Check,
  Globe,
  Radio,
  Sparkles,
  Layers,
  Lock,
  Percent
} from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const { showToast } = useToast();
  const [activeTab, setActiveTab] = useState<'weights' | 'providers' | 'apikeys'>('weights');
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);

  // Config State
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [layerWeights, setLayerWeights] = useState({
    url: 0.15,
    domain: 0.10,
    dns: 0.08,
    tls: 0.07,
    reputation: 0.20,
    ml: 0.15,
    content: 0.15,
    brand: 0.10
  });
  const [thresholds, setThresholds] = useState({
    safeMax: 35,
    suspiciousMax: 70
  });
  const [providers, setProviders] = useState({
    urlhausEnabled: true,
    phishTankEnabled: true,
    virusTotalEnabled: false
  });
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [newDomain, setNewDomain] = useState<string>('');

  // API Keys State
  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([]);
  const [newKeyName, setNewKeyName] = useState<string>('');
  const [newKeyRole, setNewKeyRole] = useState<'USER' | 'ANALYST' | 'ADMIN'>('ANALYST');
  const [createdSecret, setCreatedSecret] = useState<CreateApiKeyResponse | null>(null);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);

  useEffect(() => {
    fetchConfig();
    fetchApiKeys();
  }, []);

  const fetchConfig = async () => {
    try {
      setLoading(true);
      const res = await api.getSystemConfig();
      setConfig(res);
      setLayerWeights(res.weights);
      setThresholds(res.thresholds);
      setProviders(res.providers);
      setWhitelist(res.whitelistedDomains);
    } catch (err: any) {
      showToast('error', 'Failed to load configuration', err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchApiKeys = async () => {
    try {
      const keys = await api.listApiKeys();
      setApiKeys(keys);
    } catch (err: any) {
      console.error('Failed to load API keys:', err);
    }
  };

  const totalWeight = Object.values(layerWeights).reduce((sum, w) => sum + w, 0);

  const handleWeightChange = (layer: keyof typeof layerWeights, val: number) => {
    setLayerWeights(prev => ({ ...prev, [layer]: Math.round(val * 100) / 100 }));
  };

  const handleAutoBalance = () => {
    const keys = Object.keys(layerWeights) as (keyof typeof layerWeights)[];
    const sum = keys.reduce((acc, k) => acc + layerWeights[k], 0);
    if (sum === 0) return;
    const balanced: any = {};
    keys.forEach(k => {
      balanced[k] = Math.round((layerWeights[k] / sum) * 100) / 100;
    });
    setLayerWeights(balanced);
    showToast('info', 'Weights Auto-Balanced', 'Normalized all 8 layer weights to sum to 1.00');
  };

  const handleSaveConfig = async () => {
    try {
      setSaving(true);
      const res = await api.updateSystemConfig({
        weights: layerWeights,
        thresholds,
        providers,
        whitelistedDomains: whitelist
      });
      setConfig(res);
      showToast('success', 'Configuration Saved', 'Multi-layer risk weights and thresholds updated successfully');
    } catch (err: any) {
      showToast('error', 'Failed to save configuration', err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleResetDefaults = async () => {
    if (!confirm('Are you sure you want to reset all risk engine weights and thresholds to default factory baseline?')) return;
    try {
      setSaving(true);
      const res = await api.resetSystemConfig();
      setConfig(res);
      setLayerWeights(res.weights);
      setThresholds(res.thresholds);
      setProviders(res.providers);
      setWhitelist(res.whitelistedDomains);
      showToast('warning', 'Configuration Reset', 'Reset all risk parameters to default baseline');
    } catch (err: any) {
      showToast('error', 'Reset failed', err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleAddWhitelist = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;
    const clean = newDomain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (whitelist.includes(clean)) {
      showToast('warning', 'Domain already whitelisted', clean);
      return;
    }
    setWhitelist([...whitelist, clean]);
    setNewDomain('');
    showToast('info', 'Domain Added', `Added ${clean} to whitelist. Remember to click "Save Settings"`);
  };

  const handleRemoveWhitelist = (domain: string) => {
    setWhitelist(whitelist.filter(d => d !== domain));
  };

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;
    try {
      const res = await api.createApiKey({
        name: newKeyName.trim(),
        role: newKeyRole,
        expiresInDays: 90
      });
      setCreatedSecret(res);
      setNewKeyName('');
      await fetchApiKeys();
      showToast('success', 'API Key Generated', 'Store your secret token safely as it will not be shown again');
    } catch (err: any) {
      showToast('error', 'API Key creation failed', err.message);
    }
  };

  const handleRevokeApiKey = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this API token? Any active script using it will lose access immediately.')) return;
    try {
      await api.revokeApiKey(id);
      await fetchApiKeys();
      showToast('warning', 'API Key Revoked', `Token ID ${id} is now inactive`);
    } catch (err: any) {
      showToast('error', 'Revocation failed', err.message);
    }
  };

  const handleCopySecret = () => {
    if (!createdSecret) return;
    navigator.clipboard.writeText(createdSecret.secretToken);
    setCopiedKey(true);
    showToast('info', 'Copied to Clipboard', 'API secret token copied');
    setTimeout(() => setCopiedKey(false), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Sliders className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                System Governance & Calibration
                <span className="text-xs font-mono font-normal px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                  M9 Policy Engine
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Dynamic 8-layer weight synthesis, security thresholds, whitelist controls, and API token governance
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3">
          <button
            onClick={handleResetDefaults}
            disabled={saving}
            className="flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-semibold transition-colors disabled:opacity-50"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Defaults</span>
          </button>

          <button
            onClick={handleSaveConfig}
            disabled={saving}
            className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saving ? 'Saving...' : 'Save Settings'}</span>
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex space-x-2 border-b border-slate-800/60 pb-2">
        <button
          onClick={() => setActiveTab('weights')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
            activeTab === 'weights'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Risk Engine Calibration</span>
        </button>

        <button
          onClick={() => setActiveTab('providers')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
            activeTab === 'providers'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Feeds & Whitelisting</span>
        </button>

        <button
          onClick={() => setActiveTab('apikeys')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
            activeTab === 'apikeys'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
          }`}
        >
          <Key className="w-3.5 h-3.5" />
          <span>API Key Management</span>
        </button>
      </div>

      {/* Tab 1: Risk Engine Calibration */}
      {activeTab === 'weights' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left 2 Cols: Weight Sliders */}
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Sliders className="w-4 h-4 text-cyan-400" />
                    8-Layer Threat Weight Distribution
                  </h3>
                  <p className="text-xs text-slate-400">
                    Fine-tune the mathematical weight assigned to each detection layer in composite risk evaluation
                  </p>
                </div>
                <button
                  onClick={handleAutoBalance}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/20 text-xs font-medium transition-colors"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Auto-Balance</span>
                </button>
              </div>

              {/* Weight Sliders Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
                {[
                  { key: 'reputation', label: 'Reputation Feeds (Layer 5)', desc: 'URLhaus, PhishTank, VT', color: 'from-amber-500 to-rose-500' },
                  { key: 'ml', label: 'ML Random Forest (Layer 6)', desc: '18-dim URL lexical inference', color: 'from-indigo-500 to-cyan-500' },
                  { key: 'url', label: 'URL Lexical (Layer 1)', desc: 'Entropy, Punycode, Shortener', color: 'from-cyan-500 to-teal-500' },
                  { key: 'content', label: 'Web Content DOM (Layer 7)', desc: 'Forms, Credential harvests', color: 'from-rose-500 to-amber-500' },
                  { key: 'domain', label: 'Domain & RDAP (Layer 2)', desc: 'Domain age, Privacy guard', color: 'from-purple-500 to-indigo-500' },
                  { key: 'brand', label: 'Brand Impersonation (Layer 8)', desc: 'Keyword stuffing & mismatches', color: 'from-rose-500 to-orange-500' },
                  { key: 'dns', label: 'DNS & Infrastructure (Layer 3)', desc: 'Passive DNS & Fast-Flux', color: 'from-teal-500 to-emerald-500' },
                  { key: 'tls', label: 'TLS / SSL Socket (Layer 4)', desc: 'Cert validity & hostname SAN', color: 'from-emerald-500 to-cyan-500' }
                ].map(layer => {
                  const val = (layerWeights as any)[layer.key] || 0;
                  return (
                    <div key={layer.key} className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-200">{layer.label}</span>
                        <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/50">
                          {(val * 100).toFixed(0)}%
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400">{layer.desc}</p>
                      <input
                        type="range"
                        min="0"
                        max="0.50"
                        step="0.01"
                        value={val}
                        onChange={e => handleWeightChange(layer.key as any, parseFloat(e.target.value))}
                        className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                      />
                    </div>
                  );
                })}
              </div>

              {/* Total Weight Status Bar */}
              <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Percent className="w-4 h-4 text-slate-400" />
                  <span className="text-xs font-semibold text-slate-300">Total Mathematical Weight:</span>
                  <span
                    className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded ${
                      Math.abs(totalWeight - 1.0) < 0.01
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    {(totalWeight * 100).toFixed(0)}%
                  </span>
                </div>
                {Math.abs(totalWeight - 1.0) >= 0.01 && (
                  <span className="text-[11px] text-amber-400/90 italic">
                    Note: Weights will be automatically normalized to 100% during risk calculation.
                  </span>
                )}
              </div>
            </div>

            {/* Verdict Thresholds */}
            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm space-y-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-400" />
                Verdict Boundary Thresholds
              </h3>
              <p className="text-xs text-slate-400">
                Define the composite risk score cut-offs separating Safe, Suspicious, and Phishing verdicts
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-emerald-400">Safe Max Cut-off</span>
                    <span className="text-xs font-mono font-bold text-slate-200">≤ {thresholds.safeMax}</span>
                  </div>
                  <input
                    type="range"
                    min="15"
                    max="45"
                    value={thresholds.safeMax}
                    onChange={e => setThresholds({ ...thresholds, safeMax: parseInt(e.target.value, 10) })}
                    className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-emerald-400"
                  />
                  <p className="text-[11px] text-slate-400">Scores below this value are classified as SAFE (Low Risk).</p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-rose-400">Phishing Min Trigger</span>
                    <span className="text-xs font-mono font-bold text-slate-200">&gt; {thresholds.suspiciousMax}</span>
                  </div>
                  <input
                    type="range"
                    min="55"
                    max="85"
                    value={thresholds.suspiciousMax}
                    onChange={e => setThresholds({ ...thresholds, suspiciousMax: parseInt(e.target.value, 10) })}
                    className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-rose-400"
                  />
                  <p className="text-[11px] text-slate-400">Scores above this value trigger PHISHING verdict (High / Critical).</p>
                </div>
              </div>
            </div>
          </div>

          {/* Right Col: Live Calibration Preview & Policy Summary */}
          <div className="space-y-6">
            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm space-y-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                Live Calibration Profile
              </h3>

              <div className="space-y-2">
                {Object.entries(layerWeights).map(([k, v]) => {
                  const pct = totalWeight > 0 ? ((v / totalWeight) * 100).toFixed(1) : '0';
                  return (
                    <div key={k} className="space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="text-slate-300 uppercase font-mono">{k}</span>
                        <span className="text-slate-400 font-mono">{pct}%</span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-cyan-500 to-indigo-500 rounded-full"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="pt-4 border-t border-slate-800 space-y-2 text-xs text-slate-400">
                <div className="flex justify-between">
                  <span>Safe Range:</span>
                  <span className="font-mono text-emerald-400">0 – {thresholds.safeMax}</span>
                </div>
                <div className="flex justify-between">
                  <span>Suspicious Range:</span>
                  <span className="font-mono text-amber-400">{thresholds.safeMax + 1} – {thresholds.suspiciousMax}</span>
                </div>
                <div className="flex justify-between">
                  <span>Phishing Range:</span>
                  <span className="font-mono text-rose-400">{thresholds.suspiciousMax + 1} – 100</span>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-indigo-950/40 to-slate-900 border border-indigo-500/20 rounded-2xl p-6 space-y-3">
              <h4 className="text-xs font-bold text-indigo-300 uppercase tracking-wider flex items-center gap-1.5">
                <Lock className="w-4 h-4 text-indigo-400" />
                Zero-Trust Invariant Rules
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                Critical overrides remain enforced regardless of weight adjustments:
              </p>
              <ul className="text-xs text-slate-400 space-y-1.5 list-disc list-inside font-sans">
                <li>Brand Domain Mismatch forces score ≥ 82 (Phishing)</li>
                <li>Cross-Origin Credential Form forces score ≥ 88 (Phishing)</li>
                <li>Reputation Blacklist Hit forces score ≥ 85 (Phishing)</li>
                <li>SSRF / Private IP Resolution forces score ≥ 95 (Critical)</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Reputation Providers & Domain Whitelist */}
      {activeTab === 'providers' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Provider Toggles */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Reputation Intelligence Providers
            </h3>
            <p className="text-xs text-slate-400">
              Enable or disable integrated third-party threat feeds in Layer 5 scoring
            </p>

            <div className="space-y-3 pt-2">
              {[
                { key: 'urlhausEnabled', name: 'abuse.ch URLhaus Live Feed', desc: 'Real-time malicious URLs community database', default: true },
                { key: 'phishTankEnabled', name: 'PhishTank Community Feed', desc: 'Verified phishing submissions catalog', default: true },
                { key: 'virusTotalEnabled', name: 'VirusTotal API Adapter', desc: 'Enterprise multi-engine scanner (Requires API Key)', default: false }
              ].map(prov => {
                const isEnabled = (providers as any)[prov.key];
                return (
                  <div key={prov.key} className="flex items-center justify-between p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
                    <div>
                      <h4 className="text-xs font-bold text-slate-200">{prov.name}</h4>
                      <p className="text-[11px] text-slate-400">{prov.desc}</p>
                    </div>
                    <button
                      onClick={() => setProviders({ ...providers, [prov.key]: !isEnabled })}
                      className={`w-12 h-6 rounded-full transition-colors relative p-0.5 ${
                        isEnabled ? 'bg-cyan-500' : 'bg-slate-800'
                      }`}
                    >
                      <div
                        className={`w-5 h-5 rounded-full bg-slate-950 transition-transform ${
                          isEnabled ? 'translate-x-6' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Domain Whitelist */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              Enterprise Domain Whitelist
            </h3>
            <p className="text-xs text-slate-400">
              Whitelisted domains bypass heuristic threat alerts and are classified as trusted
            </p>

            <form onSubmit={handleAddWhitelist} className="flex gap-2">
              <input
                type="text"
                placeholder="e.g. corporate-portal.com"
                value={newDomain}
                onChange={e => setNewDomain(e.target.value)}
                className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
              <button
                type="submit"
                className="px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/30 rounded-xl text-xs font-bold transition-colors flex items-center space-x-1"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add</span>
              </button>
            </form>

            <div className="flex flex-wrap gap-2 pt-2 max-h-56 overflow-y-auto">
              {whitelist.map(domain => (
                <span
                  key={domain}
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 font-mono"
                >
                  <span>{domain}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveWhitelist(domain)}
                    className="text-slate-500 hover:text-rose-400 transition-colors"
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: API Key Management */}
      {activeTab === 'apikeys' && (
        <div className="space-y-6">
          {/* Create Key Card */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-cyan-400" />
              Generate API Access Token
            </h3>
            <p className="text-xs text-slate-400">
              Create Bearer authentication tokens for SOC automation scripts, SIEM connectors, and browser extension daemons
            </p>

            <form onSubmit={handleCreateApiKey} className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
              <input
                type="text"
                required
                placeholder="Token Name (e.g. SIEM Connector)"
                value={newKeyName}
                onChange={e => setNewKeyName(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <select
                value={newKeyRole}
                onChange={e => setNewKeyRole(e.target.value as any)}
                className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ANALYST">ANALYST Role (Standard Scans & Cases)</option>
                <option value="ADMIN">ADMIN Role (Full Policy Control)</option>
                <option value="USER">USER Role (Read-only)</option>
              </select>
              <button
                type="submit"
                className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold rounded-xl text-xs transition-all shadow-md shadow-cyan-500/20"
              >
                Generate Token
              </button>
            </form>

            {createdSecret && (
              <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-500/30 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-cyan-300">Generated Secret Bearer Token:</span>
                  <button
                    onClick={handleCopySecret}
                    className="flex items-center space-x-1 text-xs text-cyan-400 hover:text-cyan-200"
                  >
                    {copiedKey ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <code className="block p-2 bg-slate-950 rounded text-xs font-mono text-cyan-200 break-all select-all">
                  {createdSecret.secretToken}
                </code>
                <p className="text-[11px] text-amber-300/80">
                  ⚠️ This token will not be displayed again. Please save it securely in your secret manager.
                </p>
              </div>
            )}
          </div>

          {/* Active Keys Table */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Registered Service Keys</h4>
              <span className="text-xs text-slate-400 font-mono">{apiKeys.length} tokens registered</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase font-mono border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Token Name</th>
                    <th className="px-4 py-3">Key Prefix</th>
                    <th className="px-4 py-3">Role</th>
                    <th className="px-4 py-3">Created</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {apiKeys.map(key => (
                    <tr key={key.id} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 font-semibold text-white">{key.name}</td>
                      <td className="px-4 py-3 font-mono text-cyan-400">{key.keyPrefix}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                          {key.role}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-400 font-mono">{new Date(key.createdAt).toLocaleDateString()}</td>
                      <td className="px-4 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                            key.status === 'ACTIVE'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : 'bg-slate-800 text-slate-500'
                          }`}
                        >
                          {key.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        {key.status === 'ACTIVE' && (
                          <button
                            onClick={() => handleRevokeApiKey(key.id)}
                            className="text-slate-400 hover:text-rose-400 transition-colors p-1"
                            title="Revoke Key"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
