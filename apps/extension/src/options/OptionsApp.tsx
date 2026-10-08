import React, { useState, useEffect } from 'react';
import {
  Shield,
  Save,
  CheckCircle2,
  AlertCircle,
  Plus,
  Trash2,
  Server,
  Zap,
  RotateCcw,
  Sliders
} from 'lucide-react';
import { StorageService, ExtensionSettings, DEFAULT_SETTINGS } from '../utils/storage';

export const OptionsApp: React.FC = () => {
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_SETTINGS);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [newDomain, setNewDomain] = useState('');
  const [saved, setSaved] = useState(false);
  const [pingStatus, setPingStatus] = useState<{ status: 'IDLE' | 'TESTING' | 'SUCCESS' | 'ERROR'; message?: string }>({ status: 'IDLE' });
  const [cacheCleared, setCacheCleared] = useState(false);

  useEffect(() => {
    (async () => {
      const currentSettings = await StorageService.getSettings();
      const currentWhitelist = await StorageService.getWhitelist();
      setSettings(currentSettings);
      setWhitelist(currentWhitelist);
    })();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    await StorageService.saveSettings(settings);
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  const handleTestConnection = async () => {
    setPingStatus({ status: 'TESTING' });
    try {
      const res = await fetch(`${settings.apiUrl.replace(/\/$/, '')}/health`);
      if (res.ok) {
        const data = await res.json();
        setPingStatus({ status: 'SUCCESS', message: `Engine Online (${data.status || 'OK'})` });
      } else {
        setPingStatus({ status: 'ERROR', message: `HTTP ${res.status}: Engine Unreachable` });
      }
    } catch (err: any) {
      setPingStatus({ status: 'ERROR', message: err.message || 'Connection failed' });
    }
  };

  const handleAddWhitelist = async () => {
    if (!newDomain.trim()) return;
    const clean = newDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    await StorageService.addToWhitelist(clean);
    const updated = await StorageService.getWhitelist();
    setWhitelist(updated);
    setNewDomain('');
  };

  const handleRemoveWhitelist = async (domain: string) => {
    await StorageService.removeFromWhitelist(domain);
    const updated = await StorageService.getWhitelist();
    setWhitelist(updated);
  };

  const handleClearCache = () => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(null, (items) => {
        const keysToRemove = Object.keys(items).filter(k => k.startsWith('cache:'));
        chrome.storage.local.remove(keysToRemove, () => {
          setCacheCleared(true);
          setTimeout(() => setCacheCleared(false), 2000);
        });
      });
    }
  };

  return (
    <div style={{ minHeight: '100vh', background: '#030712', color: '#f3f4f6', padding: '40px 20px', boxSizing: 'border-box' }}>
      <div style={{ maxWidth: 760, margin: '0 auto' }}>
        {/* Header Banner */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #1f2937', paddingBottom: 24, marginBottom: 32 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ background: 'linear-gradient(135deg, #2563eb, #1e40af)', padding: 12, borderRadius: 12, boxShadow: '0 0 20px rgba(37, 99, 235, 0.4)' }}>
              <Shield size={28} color="#ffffff" />
            </div>
            <div>
              <h1 style={{ margin: 0, fontSize: 24, fontWeight: 800, letterSpacing: '-0.02em', color: '#ffffff' }}>
                PhishNetra Settings & Security Policies
              </h1>
              <p style={{ margin: '4px 0 0', fontSize: 13, color: '#9ca3af' }}>
                Configure zero-trust browser defense thresholds, API backend connectivity, and custom whitelist
              </p>
            </div>
          </div>

          <button
            onClick={handleSave}
            style={{
              background: '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: 8,
              padding: '10px 18px',
              fontSize: 13,
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              boxShadow: '0 4px 12px rgba(37, 99, 235, 0.3)'
            }}
          >
            {saved ? <CheckCircle2 size={16} /> : <Save size={16} />}
            {saved ? 'Saved!' : 'Save Changes'}
          </button>
        </div>

        <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          {/* Section 1: Engine Connectivity */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
              <Server size={18} color="#60a5fa" />
              <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: '#f8fafc' }}>
                PhishNetra Core Engine Connectivity
              </h2>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 6 }}>
                  Backend REST API URL
                </label>
                <input
                  type="text"
                  value={settings.apiUrl}
                  onChange={(e) => setSettings({ ...settings, apiUrl: e.target.value })}
                  placeholder="http://localhost:5000/api"
                  style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', color: '#f8fafc', padding: '10px 12px', borderRadius: 6, fontSize: 13, boxSizing: 'border-box' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 6 }}>
                  SOC Web Console URL
                </label>
                <input
                  type="text"
                  value={settings.dashboardUrl}
                  onChange={(e) => setSettings({ ...settings, dashboardUrl: e.target.value })}
                  placeholder="http://localhost:5173"
                  style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', color: '#f8fafc', padding: '10px 12px', borderRadius: 6, fontSize: 13, boxSizing: 'border-box' }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <button
                type="button"
                onClick={handleTestConnection}
                disabled={pingStatus.status === 'TESTING'}
                style={{
                  background: '#1e293b',
                  border: '1px solid #334155',
                  color: '#e2e8f0',
                  padding: '8px 14px',
                  borderRadius: 6,
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                {pingStatus.status === 'TESTING' ? 'Testing Connection...' : 'Test Connection'}
              </button>

              {pingStatus.status === 'SUCCESS' && (
                <span style={{ fontSize: 12, color: '#34d399', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <CheckCircle2 size={14} /> {pingStatus.message}
                </span>
              )}

              {pingStatus.status === 'ERROR' && (
                <span style={{ fontSize: 12, color: '#f87171', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <AlertCircle size={14} /> {pingStatus.message}
                </span>
              )}
            </div>
          </div>

          {/* Section 2: Threat Mitigation Policies */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
              <Sliders size={18} color="#a78bfa" />
              <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: '#f8fafc' }}>
                Mitigation & Interception Thresholds
              </h2>
            </div>

            <div style={{ marginBottom: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <label style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>
                  Critical Threat Interception Threshold
                </label>
                <span style={{ fontSize: 13, fontWeight: 800, color: '#60a5fa' }}>
                  {settings.blockThreshold} / 100
                </span>
              </div>
              <input
                type="range"
                min="50"
                max="95"
                step="5"
                value={settings.blockThreshold}
                onChange={(e) => setSettings({ ...settings, blockThreshold: parseInt(e.target.value, 10) })}
                style={{ width: '100%', accentColor: '#2563eb', cursor: 'pointer' }}
              />
              <div style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>
                Websites scoring above this threshold will immediately trigger the full-page security interstitial overlay.
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={settings.autoScan}
                  onChange={(e) => setSettings({ ...settings, autoScan: e.target.checked })}
                  style={{ width: 16, height: 16, accentColor: '#2563eb' }}
                />
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>Automated Live URL Scanning</div>
                  <div style={{ fontSize: 11, color: '#64748b' }}>Evaluate new tab navigations in real time via background service worker</div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={settings.enableNotifications}
                  onChange={(e) => setSettings({ ...settings, enableNotifications: e.target.checked })}
                  style={{ width: 16, height: 16, accentColor: '#2563eb' }}
                />
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>Browser Threat Notifications</div>
                  <div style={{ fontSize: 11, color: '#64748b' }}>Display non-intrusive alert when navigating to suspicious or brand-spoofing sites</div>
                </div>
              </label>
            </div>
          </div>

          {/* Section 3: Whitelisted Domains */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
              <Zap size={18} color="#34d399" />
              <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: '#f8fafc' }}>
                Trusted Whitelist
              </h2>
            </div>

            <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
              <input
                type="text"
                placeholder="e.g. internal.corp.company.com"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleAddWhitelist(); } }}
                style={{ flex: 1, background: '#1e293b', border: '1px solid #334155', color: '#f8fafc', padding: '9px 12px', borderRadius: 6, fontSize: 13 }}
              />
              <button
                type="button"
                onClick={handleAddWhitelist}
                style={{
                  background: '#10b981',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: 6,
                  padding: '9px 16px',
                  fontSize: 13,
                  fontWeight: 700,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6
                }}
              >
                <Plus size={16} /> Add Domain
              </button>
            </div>

            <div style={{ maxHeight: 180, overflowY: 'auto', border: '1px solid #1e293b', borderRadius: 8, background: '#090d16' }}>
              {whitelist.length === 0 ? (
                <div style={{ padding: 16, textAlign: 'center', fontSize: 12, color: '#64748b' }}>
                  No custom whitelisted domains configured.
                </div>
              ) : (
                whitelist.map((domain) => (
                  <div key={domain} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', borderBottom: '1px solid #1e293b' }}>
                    <span style={{ fontSize: 13, fontFamily: 'monospace', color: '#93c5fd' }}>{domain}</span>
                    <button
                      type="button"
                      onClick={() => handleRemoveWhitelist(domain)}
                      style={{ background: 'transparent', border: 'none', color: '#ef4444', cursor: 'pointer', padding: 4 }}
                      title="Remove domain"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Section 4: Cache Management */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc' }}>Local Threat Analysis Cache</div>
              <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>Purge cached threat scores to force live re-evaluation on all tabs</div>
            </div>
            <button
              type="button"
              onClick={handleClearCache}
              style={{
                background: '#334155',
                color: '#f8fafc',
                border: 'none',
                borderRadius: 6,
                padding: '8px 14px',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6
              }}
            >
              <RotateCcw size={14} />
              {cacheCleared ? 'Cache Purged!' : 'Purge Cache'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
