import React, { useState, useEffect } from 'react';
import {
  FolderLock,
  Plus,
  Search,
  Filter,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ShieldAlert,
  User,
  ExternalLink,
  RefreshCw,
  Copy,
  Check,
  Send,
  FileCode,
  ShieldCheck,
  Lock,
  Radio,
  FileText
} from 'lucide-react';
import {
  SOCCase,
  CreateCaseRequest,
  CaseStatus,
  CaseSeverity,
  RemediationType,
  RemediationResult
} from '@phishnetra/shared';
import { api } from '../services/api';

export const CaseManagementPage: React.FC = () => {
  const [cases, setCases] = useState<SOCCase[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected Case & Remediation Drawer State
  const [selectedCase, setSelectedCase] = useState<SOCCase | null>(null);
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newNoteText, setNewNoteText] = useState<string>('');
  const [generatingRemediation, setGeneratingRemediation] = useState<boolean>(false);
  const [activeRemediation, setActiveRemediation] = useState<RemediationResult | null>(null);
  const [copiedRemediation, setCopiedRemediation] = useState<boolean>(false);

  // New Case Form State
  const [newCaseTitle, setNewCaseTitle] = useState<string>('');
  const [newCaseDesc, setNewCaseDesc] = useState<string>('');
  const [newCaseSeverity, setNewCaseSeverity] = useState<CaseSeverity>('HIGH');
  const [newCaseTargetUrl, setNewCaseTargetUrl] = useState<string>('');
  const [newCaseTargetDomain, setNewCaseTargetDomain] = useState<string>('');
  const [newCaseAnalyst, setNewCaseAnalyst] = useState<string>('Alex Morgan (Tier 2)');

  useEffect(() => {
    fetchCases();
  }, [statusFilter, severityFilter]);

  const fetchCases = async () => {
    try {
      setLoading(true);
      const data = await api.listCases({
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
        severity: severityFilter !== 'ALL' ? severityFilter : undefined
      });
      setCases(data);
      if (selectedCase) {
        const updated = data.find(c => c.id === selectedCase.id);
        if (updated) setSelectedCase(updated);
      }
    } catch (err) {
      console.error('Failed to load SOC cases:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseTitle || !newCaseDesc) return;

    try {
      const created = await api.createCase({
        title: newCaseTitle,
        description: newCaseDesc,
        severity: newCaseSeverity,
        targetUrl: newCaseTargetUrl || undefined,
        targetDomain: newCaseTargetDomain || undefined,
        assignedAnalyst: newCaseAnalyst
      });
      setShowCreateModal(false);
      setNewCaseTitle('');
      setNewCaseDesc('');
      setNewCaseTargetUrl('');
      setNewCaseTargetDomain('');
      await fetchCases();
      setSelectedCase(created);
    } catch (err: any) {
      alert(`Failed to create case: ${err.message}`);
    }
  };

  const handleStatusChange = async (caseId: string, newStatus: CaseStatus) => {
    try {
      const updated = await api.updateCase(caseId, { status: newStatus });
      setSelectedCase(updated);
      await fetchCases();
    } catch (err: any) {
      alert(`Status update failed: ${err.message}`);
    }
  };

  const handleAddNote = async () => {
    if (!selectedCase || !newNoteText.trim()) return;

    try {
      const updated = await api.addCaseNote(selectedCase.id, {
        author: selectedCase.assignedAnalyst || 'SOC Analyst',
        text: newNoteText.trim()
      });
      setSelectedCase(updated);
      setNewNoteText('');
      await fetchCases();
    } catch (err: any) {
      alert(`Failed to add note: ${err.message}`);
    }
  };

  const handleRunRemediation = async (actionType: RemediationType) => {
    if (!selectedCase) return;

    try {
      setGeneratingRemediation(true);
      const res = await api.remediateCase(selectedCase.id, actionType);
      setActiveRemediation(res);
      await fetchCases();
    } catch (err: any) {
      alert(`Remediation generation failed: ${err.message}`);
    } finally {
      setGeneratingRemediation(false);
    }
  };

  const filteredCases = cases.filter(c => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.title.toLowerCase().includes(q) ||
      c.id.toLowerCase().includes(q) ||
      (c.targetDomain && c.targetDomain.toLowerCase().includes(q))
    );
  });

  const countOpen = cases.filter(c => c.status === 'OPEN').length;
  const countInvestigating = cases.filter(c => c.status === 'INVESTIGATING').length;
  const countContained = cases.filter(c => c.status === 'CONTAINED').length;
  const countResolved = cases.filter(c => c.status === 'RESOLVED').length;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 backdrop-blur-md relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-amber-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <span className="p-2 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-400">
                <FolderLock className="w-6 h-6" />
              </span>
              <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
                SOC Incident Response & Case Management
              </h1>
            </div>
            <p className="text-slate-400 text-sm">
              End-to-end investigation lifecycle, evidence timeline correlation, and 1-click active remediation defense generator (DNS RPZ, Firewall, Abuse notices).
            </p>
          </div>

          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-slate-950 font-semibold px-4 py-2.5 rounded-lg text-sm transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Open New Case</span>
          </button>
        </div>

        {/* Case Stats Ribbon */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-slate-800/80">
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
            <div className="text-[11px] text-slate-400 font-medium">Open Cases</div>
            <div className="text-xl font-bold text-amber-400 font-mono mt-0.5">{countOpen}</div>
          </div>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
            <div className="text-[11px] text-slate-400 font-medium">Under Investigation</div>
            <div className="text-xl font-bold text-cyan-400 font-mono mt-0.5">{countInvestigating}</div>
          </div>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
            <div className="text-[11px] text-slate-400 font-medium">Contained / Sinkholed</div>
            <div className="text-xl font-bold text-purple-400 font-mono mt-0.5">{countContained}</div>
          </div>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
            <div className="text-[11px] text-slate-400 font-medium">Resolved</div>
            <div className="text-xl font-bold text-emerald-400 font-mono mt-0.5">{countResolved}</div>
          </div>
        </div>
      </div>

      {/* Main Grid: Cases List + Investigation Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Cases Table (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* Filter Bar */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row gap-3 items-center justify-between">
            <div className="relative w-full sm:w-64">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search cases, domains..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-amber-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="OPEN">Open</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="CONTAINED">Contained</option>
                <option value="RESOLVED">Resolved</option>
                <option value="FALSE_POSITIVE">False Positive</option>
              </select>

              <select
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-amber-500"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>

          {/* Cases List */}
          <div className="space-y-3">
            {loading ? (
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-12 text-center text-slate-500 text-sm">
                <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-amber-400" />
                Loading SOC incident cases...
              </div>
            ) : filteredCases.length === 0 ? (
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-12 text-center text-slate-500 text-sm">
                No incident response cases matching your filters.
              </div>
            ) : (
              filteredCases.map(c => {
                const isSelected = selectedCase?.id === c.id;
                const isCrit = c.severity === 'CRITICAL';
                return (
                  <div
                    key={c.id}
                    onClick={() => {
                      setSelectedCase(c);
                      setActiveRemediation(null);
                    }}
                    className={`bg-slate-900/80 border rounded-xl p-4 cursor-pointer transition-all ${
                      isSelected
                        ? 'border-amber-500/70 bg-amber-950/10 shadow-lg shadow-amber-950/20'
                        : 'border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3 mb-2">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-mono text-xs font-bold text-amber-400">
                            {c.id}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            isCrit
                              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                              : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          }`}>
                            {c.severity}
                          </span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300">
                            {c.status}
                          </span>
                        </div>
                        <h4 className="text-sm font-semibold text-slate-100 line-clamp-1">
                          {c.title}
                        </h4>
                      </div>

                      <div className="text-[11px] text-slate-500 font-mono">
                        {new Date(c.updatedAt).toLocaleTimeString()}
                      </div>
                    </div>

                    <p className="text-xs text-slate-400 line-clamp-2 mb-3">
                      {c.description}
                    </p>

                    <div className="flex items-center justify-between text-[11px] text-slate-500 pt-2 border-t border-slate-800/60 font-mono">
                      <span>Analyst: <strong className="text-slate-300">{c.assignedAnalyst}</strong></span>
                      <span>IOCs: <strong className="text-slate-300">{c.iocs.domains.length + c.iocs.ips.length + c.iocs.urls.length}</strong></span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Case Detail & Remediation Workbench (5 Cols) */}
        <div className="lg:col-span-5 space-y-4">
          {selectedCase ? (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-5">
              {/* Header & Status Controller */}
              <div className="flex items-start justify-between gap-3 pb-4 border-b border-slate-800">
                <div>
                  <div className="text-xs font-mono text-amber-400 font-bold mb-0.5">
                    {selectedCase.id}
                  </div>
                  <h3 className="text-base font-bold text-slate-100">
                    {selectedCase.title}
                  </h3>
                </div>

                <select
                  value={selectedCase.status}
                  onChange={e => handleStatusChange(selectedCase.id, e.target.value as CaseStatus)}
                  className="bg-slate-950 border border-slate-700 text-amber-300 rounded-lg px-2.5 py-1 text-xs font-semibold focus:outline-none focus:border-amber-500"
                >
                  <option value="OPEN">OPEN</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="CONTAINED">CONTAINED</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
                </select>
              </div>

              {/* Target Infrastructure */}
              <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-2 text-xs font-mono">
                <div>
                  <span className="text-slate-500">TARGET DOMAIN:</span>{' '}
                  <span className="text-slate-200 font-bold">{selectedCase.targetDomain || 'N/A'}</span>
                </div>
                {selectedCase.targetUrl && (
                  <div className="truncate">
                    <span className="text-slate-500">TARGET URL:</span>{' '}
                    <span className="text-cyan-400">{selectedCase.targetUrl}</span>
                  </div>
                )}
                <div>
                  <span className="text-slate-500">ASSIGNED ANALYST:</span>{' '}
                  <span className="text-slate-300">{selectedCase.assignedAnalyst}</span>
                </div>
              </div>

              {/* Remediation Action Toolkit */}
              <div className="space-y-2">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
                  Active Remediation Defense Generator
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <button
                    onClick={() => handleRunRemediation('DNS_SINKHOLE')}
                    disabled={generatingRemediation}
                    className="px-2.5 py-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-left text-xs transition-colors"
                  >
                    <div className="font-bold text-cyan-400">DNS Sinkhole</div>
                    <div className="text-[10px] text-slate-500">RPZ Bind9 Rule</div>
                  </button>

                  <button
                    onClick={() => handleRunRemediation('FIREWALL_BLOCK')}
                    disabled={generatingRemediation}
                    className="px-2.5 py-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-left text-xs transition-colors"
                  >
                    <div className="font-bold text-red-400">Firewall Drop</div>
                    <div className="text-[10px] text-slate-500">Iptables / Snort</div>
                  </button>

                  <button
                    onClick={() => handleRunRemediation('TAKEDOWN_NOTICE')}
                    disabled={generatingRemediation}
                    className="px-2.5 py-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-left text-xs transition-colors"
                  >
                    <div className="font-bold text-amber-400">Abuse Notice</div>
                    <div className="text-[10px] text-slate-500">RFC 2142 Letter</div>
                  </button>
                </div>

                {activeRemediation && (
                  <div className="bg-slate-950 border border-amber-500/40 rounded-lg p-3.5 space-y-2 mt-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-bold text-amber-300">
                        Generated {activeRemediation.actionType} Artifact
                      </span>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(activeRemediation.generatedArtifact);
                          setCopiedRemediation(true);
                          setTimeout(() => setCopiedRemediation(false), 2000);
                        }}
                        className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200"
                      >
                        {copiedRemediation ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedRemediation ? 'Copied' : 'Copy Rule'}</span>
                      </button>
                    </div>
                    <pre className="text-[11px] font-mono text-slate-300 bg-slate-900 p-2.5 rounded border border-slate-800 whitespace-pre-wrap max-h-40 overflow-y-auto">
                      {activeRemediation.generatedArtifact}
                    </pre>
                    <div className="text-[10px] text-slate-400 italic">
                      {activeRemediation.instructions}
                    </div>
                  </div>
                )}
              </div>

              {/* Timeline Audit Trail */}
              <div className="space-y-2">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                  Investigation Timeline ({selectedCase.timeline.length})
                </div>

                <div className="space-y-2 max-h-36 overflow-y-auto pr-1">
                  {selectedCase.timeline.map((tl, idx) => (
                    <div key={idx} className="text-xs bg-slate-950 p-2.5 rounded border border-slate-800/80">
                      <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono mb-0.5">
                        <span className="font-bold text-slate-300">{tl.action}</span>
                        <span>{new Date(tl.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <div className="text-slate-400 text-[11px]">{tl.details}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Analyst Notes Thread */}
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-slate-400" />
                  Analyst Notes & Log Thread
                </div>

                <div className="space-y-2 max-h-32 overflow-y-auto pr-1">
                  {selectedCase.notes.length === 0 ? (
                    <div className="text-xs text-slate-500 italic">No notes recorded yet.</div>
                  ) : (
                    selectedCase.notes.map((n, i) => (
                      <div key={i} className="bg-slate-950 p-2.5 rounded border border-slate-800/80 text-xs">
                        <div className="flex items-center justify-between text-[10px] text-amber-400/80 font-mono mb-1">
                          <span>{n.author}</span>
                          <span className="text-slate-500">{new Date(n.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <p className="text-slate-300 text-[11px]">{n.text}</p>
                      </div>
                    ))
                  )}
                </div>

                <div className="flex gap-2 pt-1">
                  <input
                    type="text"
                    placeholder="Add an investigation note..."
                    value={newNoteText}
                    onChange={e => setNewNoteText(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter') handleAddNote();
                    }}
                    className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
                  />
                  <button
                    onClick={handleAddNote}
                    className="px-3 py-1.5 bg-amber-500 hover:bg-amber-400 text-slate-950 rounded-lg text-xs font-semibold transition-colors"
                  >
                    <Send className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-12 text-center text-slate-500 text-sm">
              Select an incident case to view investigation telemetry and launch remediation.
            </div>
          )}
        </div>
      </div>

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 mb-4">
              Open New SOC Incident Case
            </h3>
            <form onSubmit={handleCreateCase} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">CASE TITLE</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Credential Harvester Impersonating PayPal Portal"
                  value={newCaseTitle}
                  onChange={e => setNewCaseTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">INCIDENT SUMMARY</label>
                <textarea
                  required
                  rows={3}
                  placeholder="Describe detected threat characteristics and impact..."
                  value={newCaseDesc}
                  onChange={e => setNewCaseDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500 resize-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">SEVERITY</label>
                  <select
                    value={newCaseSeverity}
                    onChange={e => setNewCaseSeverity(e.target.value as CaseSeverity)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">ASSIGNED ANALYST</label>
                  <input
                    type="text"
                    value={newCaseAnalyst}
                    onChange={e => setNewCaseAnalyst(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">TARGET DOMAIN (OPTIONAL)</label>
                  <input
                    type="text"
                    placeholder="paypal-verify.top"
                    value={newCaseTargetDomain}
                    onChange={e => setNewCaseTargetDomain(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">TARGET URL (OPTIONAL)</label>
                  <input
                    type="text"
                    placeholder="https://paypal-verify.top/auth"
                    value={newCaseTargetUrl}
                    onChange={e => setNewCaseTargetUrl(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-amber-500 hover:bg-amber-400 text-slate-950 rounded-lg text-xs font-semibold"
                >
                  Open Incident Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
