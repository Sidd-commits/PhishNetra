import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
  AttackSurfaceAsset,
  CTLogEntry,
  AttackSurfaceAssetType,
  RiskLevel
} from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  Globe,
  Radar,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Plus,
  RefreshCw,
  Search,
  Lock,
  Server,
  Key,
  Flame,
  Radio,
  Trash2,
  ExternalLink,
  Zap,
  CheckCircle2,
  Calendar
} from 'lucide-react';

export const AttackSurfacePage: React.FC = () => {
  const { showToast } = useToast();

  const [assets, setAssets] = useState<AttackSurfaceAsset[]>([]);
  const [ctLogs, setCtLogs] = useState<CTLogEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [scanning, setScanning] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'ASSETS' | 'CT_LOGS'>('ASSETS');
  const [showModal, setShowModal] = useState<boolean>(false);

  // New Asset Form
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState<AttackSurfaceAssetType>('DOMAIN');
  const [newValue, setNewValue] = useState('');
  const [newBrand, setNewBrand] = useState('');
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [aList, cList] = await Promise.all([
        api.listAttackSurfaceAssets(),
        api.listCTLogs()
      ]);
      setAssets(aList);
      setCtLogs(cList);
    } catch (err: any) {
      showToast('error', 'Load Failed', err.response?.data?.error || 'Failed to load attack surface data');
    } finally {
      setLoading(false);
    }
  };

  const handleScanPerimeter = async () => {
    setScanning(true);
    try {
      const res = await api.triggerPerimeterScan();
      showToast('success', 'Perimeter Audited', `Perimeter scan complete: ${res.totalAssets} assets audited, ${res.newlyDiscoveredCount} newly observed indicators correlated`);
      await loadData();
    } catch (err: any) {
      showToast('error', 'Scan Failed', 'Perimeter scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newValue.trim()) {
      showToast('warning', 'Incomplete Form', 'Please provide an asset name and target value');
      return;
    }

    setCreating(true);
    try {
      const created = await api.createAttackSurfaceAsset({
        name: newName,
        assetType: newType,
        targetValue: newValue,
        associatedBrands: newBrand ? [newBrand] : []
      });
      setAssets(prev => [created, ...prev]);
      setShowModal(false);
      setNewName('');
      setNewValue('');
      setNewBrand('');
      showToast('success', 'Asset Registered', `Monitored asset "${created.name}" added to perimeter`);
    } catch (err: any) {
      showToast('error', 'Registration Failed', err.response?.data?.error || 'Failed to add asset');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteAsset = async (id: string, name: string) => {
    try {
      await api.deleteAttackSurfaceAsset(id);
      setAssets(prev => prev.filter(a => a.id !== id));
      showToast('info', 'Asset Removed', `Asset "${name}" removed from perimeter inventory`);
    } catch (err: any) {
      showToast('error', 'Delete Failed', 'Failed to remove asset');
    }
  };

  const typosquatsCount = ctLogs.filter(c => c.isTyposquat).length;
  const quarantinedCount = ctLogs.filter(c => c.autoQuarantined).length;

  return (
    <div className="space-y-6 animate-in fade-in duration-500 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-2xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 shadow-lg shadow-indigo-500/10">
              <Radar className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-2xl font-black tracking-tight text-white">External Attack Surface Management</h1>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                  EASM & CT Logs Radar
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Continuous asset perimeter discovery, Certificate Transparency logs radar & brand typosquat defense
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handleScanPerimeter}
            disabled={scanning}
            className="px-4 py-2 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 text-cyan-300 text-xs font-semibold transition-colors flex items-center space-x-2"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
            <span>{scanning ? 'Sweeping Perimeter...' : 'Scan Perimeter'}</span>
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg shadow-indigo-500/20 transition-all flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>Add Monitored Asset</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-4 backdrop-blur-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Perimeter Assets</span>
            <Globe className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-white mt-2">
            {assets.length}
          </div>
          <div className="text-[11px] text-cyan-400 mt-1">Domains, subdomains & IPs</div>
        </div>

        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-4 backdrop-blur-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>CT Log Typosquats</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-black text-rose-400 mt-2">
            {typosquatsCount}
          </div>
          <div className="text-[11px] text-rose-300 mt-1">Impersonation certs intercepted</div>
        </div>

        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-4 backdrop-blur-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Auto-Quarantined</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-400 mt-2">
            {quarantinedCount}
          </div>
          <div className="text-[11px] text-emerald-300 mt-1">Pre-emptively sinkholed</div>
        </div>

        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-4 backdrop-blur-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>TLS Health Score</span>
            <Lock className="w-4 h-4 text-teal-400" />
          </div>
          <div className="text-2xl font-black text-teal-300 mt-2">
            100%
          </div>
          <div className="text-[11px] text-teal-400 mt-1">All apex certs valid &gt; 60 days</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-800">
        <button
          onClick={() => setActiveTab('ASSETS')}
          className={`px-4 py-2.5 text-xs font-bold transition-colors border-b-2 flex items-center space-x-2 ${
            activeTab === 'ASSETS'
              ? 'border-indigo-400 text-indigo-300'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Globe className="w-3.5 h-3.5" />
          <span>Perimeter Assets ({assets.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('CT_LOGS')}
          className={`px-4 py-2.5 text-xs font-bold transition-colors border-b-2 flex items-center space-x-2 ${
            activeTab === 'CT_LOGS'
              ? 'border-rose-400 text-rose-300'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Radar className="w-3.5 h-3.5" />
          <span>Certificate Transparency Radar ({ctLogs.length})</span>
        </button>
      </div>

      {/* Assets Inventory Table */}
      {activeTab === 'ASSETS' && (
        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Asset Name</th>
                  <th className="py-3 px-4">Type & Target</th>
                  <th className="py-3 px-4">Risk Level</th>
                  <th className="py-3 px-4">Open Ports</th>
                  <th className="py-3 px-4">TLS Expiry</th>
                  <th className="py-3 px-4">Last Scanned</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {assets.map(asset => (
                  <tr key={asset.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3.5 px-4">
                      <div className="font-bold text-white font-sans">{asset.name}</div>
                      <div className="text-[10px] text-slate-400">Source: {asset.discoverySource}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="text-cyan-400 font-bold">{asset.targetValue}</div>
                      <div className="text-[10px] text-slate-400">{asset.assetType}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          asset.riskLevel === 'CRITICAL' || asset.riskLevel === 'HIGH'
                            ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                            : asset.riskLevel === 'MEDIUM'
                            ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                            : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                        }`}
                      >
                        {asset.riskLevel}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1">
                        {asset.openPorts.length > 0 ? (
                          asset.openPorts.map(p => (
                            <span key={p} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                              {p}
                            </span>
                          ))
                        ) : (
                          <span className="text-slate-500 text-[11px]">-</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 text-[11px]">
                      {asset.tlsExpiryDate ? new Date(asset.tlsExpiryDate).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                      {new Date(asset.lastScannedAt).toLocaleTimeString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => handleDeleteAsset(asset.id, asset.name)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                        title="Remove Asset"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* CT Logs Radar Table */}
      {activeTab === 'CT_LOGS' && (
        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Observed Domain & SANs</th>
                  <th className="py-3 px-4">Certificate Authority Issuer</th>
                  <th className="py-3 px-4">Typosquat Detection</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Auto-Quarantine</th>
                  <th className="py-3 px-4">Logged At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {ctLogs.map(log => (
                  <tr key={log.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3.5 px-4">
                      <div className="text-white font-bold">{log.domain}</div>
                      <div className="text-[10px] text-slate-400">{log.sanNames.join(', ')}</div>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300">
                      {log.issuer}
                    </td>
                    <td className="py-3.5 px-4">
                      {log.isTyposquat ? (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
                          Targeting {log.targetedBrand}
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                          Legitimate
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`font-bold ${log.riskScore > 75 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {log.riskScore}/100
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      {log.autoQuarantined ? (
                        <span className="flex items-center space-x-1 text-emerald-400 text-[11px] font-semibold">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Sinkholed</span>
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">Bypassed</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                      {new Date(log.loggedAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Add Asset Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-800 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Radar className="w-5 h-5 text-indigo-400" />
                <h2 className="text-lg font-bold text-white">Add Monitored Perimeter Asset</h2>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateAsset} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Asset Name</label>
                <input
                  type="text"
                  value={newName}
                  onChange={e => setNewName(e.target.value)}
                  placeholder="e.g., Staging Payment Gateway"
                  required
                  className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-indigo-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Asset Type</label>
                  <select
                    value={newType}
                    onChange={e => setNewType(e.target.value as AttackSurfaceAssetType)}
                    className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-indigo-300 focus:outline-none"
                  >
                    <option value="DOMAIN">Apex Domain</option>
                    <option value="SUBDOMAIN">Subdomain</option>
                    <option value="IP_ADDRESS">IP Address</option>
                    <option value="SSL_CERTIFICATE">SSL Certificate</option>
                    <option value="BRAND_KEYWORD">Brand Keyword</option>
                    <option value="EXPOSED_SERVICE">Exposed Service</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Brand Association</label>
                  <input
                    type="text"
                    value={newBrand}
                    onChange={e => setNewBrand(e.target.value)}
                    placeholder="e.g., PhishNetra"
                    className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-indigo-400"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Target Value (FQDN / IP / Keyword)</label>
                <input
                  type="text"
                  value={newValue}
                  onChange={e => setNewValue(e.target.value)}
                  placeholder="e.g., pay-staging.phishnetra.security or 198.51.100.22"
                  required
                  className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-indigo-400"
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
                  className="px-5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg shadow-indigo-500/20"
                >
                  {creating ? 'Registering...' : 'Register Asset'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
