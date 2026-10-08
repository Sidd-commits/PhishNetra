import React, { useState, useEffect } from 'react';
import {
  Server,
  Send,
  Download,
  Copy,
  Check,
  Plus,
  Trash2,
  Play,
  RefreshCw,
  Bell,
  Code2,
  CheckCircle2,
  AlertTriangle,
  Radio,
  ExternalLink,
  ShieldCheck,
  Zap,
  Terminal,
  FileText
} from 'lucide-react';
import {
  SIEMFormat,
  SIEMExportResult,
  WebhookConfig,
  CreateWebhookRequest,
  WebhookDeliveryLog
} from '@phishnetra/shared';
import { api } from '../services/api';

export const SIEMIntegrationPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'siem' | 'webhooks' | 'logs'>('siem');

  // SIEM State
  const [selectedFormat, setSelectedFormat] = useState<SIEMFormat>('CEF');
  const [siemResult, setSiemResult] = useState<SIEMExportResult | null>(null);
  const [loadingExport, setLoadingExport] = useState<boolean>(false);
  const [copiedPayload, setCopiedPayload] = useState<boolean>(false);
  const [copiedFeedUrl, setCopiedFeedUrl] = useState<boolean>(false);

  // Webhooks State
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([]);
  const [loadingWebhooks, setLoadingWebhooks] = useState<boolean>(true);
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [testingWebhookId, setTestingWebhookId] = useState<string | null>(null);
  const [deliveryLogs, setDeliveryLogs] = useState<WebhookDeliveryLog[]>([]);

  // New Webhook Form State
  const [newWhName, setNewWhName] = useState<string>('');
  const [newWhUrl, setNewWhUrl] = useState<string>('');
  const [newWhType, setNewWhType] = useState<'SLACK' | 'TEAMS' | 'DISCORD' | 'GENERIC_HTTP' | 'PAGERDUTY'>('SLACK');
  const [newWhSeverity, setNewWhSeverity] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM'>('HIGH');
  const [newWhSecret, setNewWhSecret] = useState<string>('');

  useEffect(() => {
    fetchExport(selectedFormat);
    fetchWebhooks();
    fetchLogs();
  }, []);

  const fetchExport = async (format: SIEMFormat) => {
    try {
      setLoadingExport(true);
      const res = await api.exportSIEM({ format, includeRawPayload: false });
      setSiemResult(res);
    } catch (err) {
      console.error('Failed to export SIEM logs:', err);
    } finally {
      setLoadingExport(false);
    }
  };

  const fetchWebhooks = async () => {
    try {
      setLoadingWebhooks(true);
      const list = await api.listWebhooks();
      setWebhooks(list);
    } catch (err) {
      console.error('Failed to load webhooks:', err);
    } finally {
      setLoadingWebhooks(false);
    }
  };

  const fetchLogs = async () => {
    try {
      const logs = await api.getWebhookLogs(20);
      setDeliveryLogs(logs);
    } catch (err) {
      console.error('Failed to load logs:', err);
    }
  };

  const handleFormatChange = (fmt: SIEMFormat) => {
    setSelectedFormat(fmt);
    fetchExport(fmt);
  };

  const handleCopyPayload = () => {
    if (!siemResult) return;
    navigator.clipboard.writeText(siemResult.formattedOutput);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  const handleCopyFeedUrl = () => {
    const feedUrl = `http://localhost:5000/api/siem/feed?format=${selectedFormat}`;
    navigator.clipboard.writeText(feedUrl);
    setCopiedFeedUrl(true);
    setTimeout(() => setCopiedFeedUrl(false), 2000);
  };

  const handleDownload = () => {
    if (!siemResult) return;
    const blob = new Blob([siemResult.formattedOutput], { type: siemResult.contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishnetra-siem-export-${selectedFormat.toLowerCase()}.${selectedFormat === 'SENTINEL_JSON' || selectedFormat === 'SPLUNK_HEC' ? 'json' : 'log'}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWhName || !newWhUrl) return;

    try {
      await api.createWebhook({
        name: newWhName,
        url: newWhUrl,
        channelType: newWhType,
        minSeverity: newWhSeverity as any,
        secretKey: newWhSecret || undefined,
        enabled: true
      });
      setShowAddModal(false);
      setNewWhName('');
      setNewWhUrl('');
      setNewWhSecret('');
      await fetchWebhooks();
    } catch (err: any) {
      alert(`Failed to create webhook: ${err.message}`);
    }
  };

  const handleDeleteWebhook = async (id: string) => {
    if (!confirm('Are you sure you want to remove this webhook?')) return;
    try {
      await api.deleteWebhook(id);
      await fetchWebhooks();
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  const handleTestWebhook = async (id: string) => {
    try {
      setTestingWebhookId(id);
      await api.testWebhook(id);
      await fetchLogs();
      alert('Test alert payload dispatched successfully!');
    } catch (err: any) {
      alert(`Test failed: ${err.message}`);
    } finally {
      setTestingWebhookId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 backdrop-blur-md relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <span className="p-2 bg-indigo-500/10 border border-indigo-500/30 rounded-lg text-indigo-400">
                <Server className="w-6 h-6" />
              </span>
              <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
                Enterprise SIEM / SOAR & Alert Webhooks
              </h1>
            </div>
            <p className="text-slate-400 text-sm">
              Standardized telemetry export for Splunk, ArcSight CEF, IBM QRadar LEEF, Microsoft Sentinel, and real-time webhook incident dispatchers.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleCopyFeedUrl}
              className="flex items-center gap-2 bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 px-3.5 py-2 rounded-lg text-xs font-mono transition-colors"
            >
              {copiedFeedUrl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
              <span>Live SIEM Feed Endpoint</span>
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 space-x-2">
        <button
          onClick={() => setActiveTab('siem')}
          className={`flex items-center gap-2 px-4 py-3 font-medium text-sm transition-all border-b-2 -mb-px ${
            activeTab === 'siem'
              ? 'border-indigo-400 text-indigo-400 bg-indigo-500/10 rounded-t-lg'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 rounded-t-lg'
          }`}
        >
          <Code2 className="w-4 h-4" />
          SIEM Format Generator
        </button>

        <button
          onClick={() => setActiveTab('webhooks')}
          className={`flex items-center gap-2 px-4 py-3 font-medium text-sm transition-all border-b-2 -mb-px ${
            activeTab === 'webhooks'
              ? 'border-indigo-400 text-indigo-400 bg-indigo-500/10 rounded-t-lg'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 rounded-t-lg'
          }`}
        >
          <Bell className="w-4 h-4" />
          Notification Webhooks ({webhooks.length})
        </button>

        <button
          onClick={() => setActiveTab('logs')}
          className={`flex items-center gap-2 px-4 py-3 font-medium text-sm transition-all border-b-2 -mb-px ${
            activeTab === 'logs'
              ? 'border-indigo-400 text-indigo-400 bg-indigo-500/10 rounded-t-lg'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 rounded-t-lg'
          }`}
        >
          <FileText className="w-4 h-4" />
          Delivery Logs
        </button>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: SIEM Multi-Format Exporter                                        */}
      {/* ========================================================================= */}
      {activeTab === 'siem' && (
        <div className="space-y-6">
          {/* Format Selector Pills */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div>
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Select Target SIEM Schema
                </div>
                <div className="flex flex-wrap gap-2">
                  {[
                    { id: 'CEF', name: 'ArcSight CEF', desc: 'Common Event Format' },
                    { id: 'LEEF', name: 'IBM QRadar LEEF', desc: 'Log Event Extended Format' },
                    { id: 'SYSLOG_RFC5424', name: 'Syslog RFC5424', desc: 'Elastic / Graylog' },
                    { id: 'SENTINEL_JSON', name: 'Microsoft Sentinel', desc: 'Azure Log Analytics' },
                    { id: 'SPLUNK_HEC', name: 'Splunk HEC', desc: 'HTTP Event Collector' }
                  ].map(fmt => (
                    <button
                      key={fmt.id}
                      onClick={() => handleFormatChange(fmt.id as SIEMFormat)}
                      className={`px-3.5 py-2 rounded-lg text-xs font-medium border transition-all text-left ${
                        selectedFormat === fmt.id
                          ? 'bg-indigo-500/20 text-indigo-300 border-indigo-500/50 shadow-sm'
                          : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:border-slate-700 hover:text-slate-200'
                      }`}
                    >
                      <div className="font-semibold">{fmt.name}</div>
                      <div className="text-[10px] text-slate-500">{fmt.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyPayload}
                  className="flex items-center gap-1.5 px-3 py-2 bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-200 rounded-lg text-xs font-medium transition-colors"
                >
                  {copiedPayload ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedPayload ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  onClick={handleDownload}
                  className="flex items-center gap-1.5 px-3 py-2 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 rounded-lg text-xs font-medium transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download</span>
                </button>
              </div>
            </div>
          </div>

          {/* Live Formatted Output Screen */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl font-mono">
            <div className="bg-slate-900/90 border-b border-slate-800 px-4 py-2.5 flex items-center justify-between text-xs text-slate-400">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-indigo-400" />
                <span>Formatted Output • {siemResult?.eventCount || 0} event(s) generated</span>
              </div>
              <div className="text-[11px] text-slate-500">
                Type: {siemResult?.contentType}
              </div>
            </div>

            <div className="p-4 overflow-x-auto max-h-[500px]">
              {loadingExport ? (
                <div className="flex items-center justify-center py-16 text-slate-500 text-sm gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
                  Formatting threat events...
                </div>
              ) : (
                <pre className="text-xs text-indigo-300/90 leading-relaxed whitespace-pre font-mono">
                  {siemResult?.formattedOutput || 'No threat events to format.'}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: Webhook Alert Dispatchers                                         */}
      {/* ========================================================================= */}
      {activeTab === 'webhooks' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-semibold text-slate-100">
                Incident Response Webhooks
              </h3>
              <p className="text-xs text-slate-400">
                Outbound alerting webhooks triggered when critical phishing campaigns or high-risk domains are flagged.
              </p>
            </div>
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-indigo-500 hover:bg-indigo-400 text-slate-950 rounded-lg text-xs font-semibold transition-colors"
            >
              <Plus className="w-4 h-4" />
              <span>Add Webhook</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {webhooks.map(wh => (
              <div
                key={wh.id}
                className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-semibold text-sm text-slate-100">{wh.name}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                        {wh.channelType}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 font-mono truncate max-w-sm" title={wh.url}>
                      {wh.url}
                    </div>
                  </div>

                  <button
                    onClick={() => handleDeleteWebhook(wh.id)}
                    className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>

                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                  <div className="text-slate-400">
                    Min Severity: <strong className="text-slate-200">{wh.minSeverity}</strong>
                  </div>

                  <button
                    onClick={() => handleTestWebhook(wh.id)}
                    disabled={testingWebhookId === wh.id}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 rounded-lg text-xs transition-colors disabled:opacity-50"
                  >
                    {testingWebhookId === wh.id ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-indigo-400" />
                    ) : (
                      <Send className="w-3.5 h-3.5 text-indigo-400" />
                    )}
                    <span>Test Dispatch</span>
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Add Webhook Modal */}
          {showAddModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 shadow-2xl">
                <h3 className="text-base font-bold text-slate-100 mb-4">
                  Configure New Alert Webhook
                </h3>
                <form onSubmit={handleCreateWebhook} className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">CHANNEL NAME</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. Primary SOC Slack Alerts"
                      value={newWhName}
                      onChange={e => setNewWhName(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">WEBHOOK URL</label>
                    <input
                      type="url"
                      required
                      placeholder="https://alerts.yourdomain.com/webhook"
                      value={newWhUrl}
                      onChange={e => setNewWhUrl(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 font-mono"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-slate-400 mb-1">CHANNEL TYPE</label>
                      <select
                        value={newWhType}
                        onChange={e => setNewWhType(e.target.value as any)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                      >
                        <option value="SLACK">Slack BlockKit</option>
                        <option value="DISCORD">Discord Webhook</option>
                        <option value="TEAMS">Microsoft Teams</option>
                        <option value="GENERIC_HTTP">Generic HTTP / HMAC</option>
                        <option value="PAGERDUTY">PagerDuty V2</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-400 mb-1">MIN SEVERITY</label>
                      <select
                        value={newWhSeverity}
                        onChange={e => setNewWhSeverity(e.target.value as any)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                      >
                        <option value="CRITICAL">CRITICAL only</option>
                        <option value="HIGH">HIGH & CRITICAL</option>
                        <option value="MEDIUM">MEDIUM and above</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">HMAC SECRET KEY (OPTIONAL)</label>
                    <input
                      type="password"
                      placeholder="Optional SHA-256 signing secret"
                      value={newWhSecret}
                      onChange={e => setNewWhSecret(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 font-mono"
                    />
                  </div>

                  <div className="flex items-center justify-end gap-3 pt-2">
                    <button
                      type="button"
                      onClick={() => setShowAddModal(false)}
                      className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-4 py-2 bg-indigo-500 hover:bg-indigo-400 text-slate-950 rounded-lg text-xs font-semibold"
                    >
                      Save Webhook
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: Delivery Logs                                                     */}
      {/* ========================================================================= */}
      {activeTab === 'logs' && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-slate-100">
              Recent Webhook Dispatch Telemetry
            </h3>
            <button
              onClick={fetchLogs}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase">
                  <th className="pb-3 font-semibold">Timestamp</th>
                  <th className="pb-3 font-semibold">Webhook Target</th>
                  <th className="pb-3 font-semibold">Event</th>
                  <th className="pb-3 font-semibold">Status</th>
                  <th className="pb-3 font-semibold">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {deliveryLogs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500 font-sans">
                      No webhook deliveries recorded yet.
                    </td>
                  </tr>
                ) : (
                  deliveryLogs.map((log, i) => (
                    <tr key={i} className="hover:bg-slate-800/30">
                      <td className="py-3 text-slate-400">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-3 font-bold text-slate-200">
                        {log.webhookName} ({log.channelType})
                      </td>
                      <td className="py-3 text-indigo-400">
                        {log.event}
                      </td>
                      <td className="py-3">
                        {log.success ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                            HTTP {log.statusCode || 200} OK
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                            FAILED ({log.error || 'Network error'})
                          </span>
                        )}
                      </td>
                      <td className="py-3 text-slate-400 max-w-xs truncate" title={log.payloadSummary}>
                        {log.payloadSummary}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
