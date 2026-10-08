import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import { TakedownNotice, TakedownStatus, TakedownNoticeType } from '@phishnetra/shared';
import {
  Gavel,
  ShieldAlert,
  Send,
  CheckCircle2,
  Clock,
  Ban,
  FileText,
  AlertTriangle,
  Plus,
  RefreshCw,
  ExternalLink,
  Copy,
  Mail,
  Search,
  Filter,
  Globe
} from 'lucide-react';

export const TakedownCenterPage: React.FC = () => {
  const { showToast } = useToast();
  const [notices, setNotices] = useState<TakedownNotice[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [selectedNotice, setSelectedNotice] = useState<TakedownNotice | null>(null);

  // Modal State
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [targetBrand, setTargetBrand] = useState<string>('');
  const [noticeType, setNoticeType] = useState<TakedownNoticeType>('RFC2142_ABUSE_NOTICE');
  const [customNotes, setCustomNotes] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  useEffect(() => {
    fetchNotices();
  }, [statusFilter]);

  const fetchNotices = async () => {
    try {
      setLoading(true);
      const data = await api.listTakedowns(statusFilter || undefined);
      setNotices(data);
      if (data.length > 0 && !selectedNotice) {
        setSelectedNotice(data[0]);
      }
    } catch (err: any) {
      showToast('error', 'Failed to load takedowns', err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateNotice = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    try {
      setIsSubmitting(true);
      const notice = await api.createTakedown({
        targetUrl: targetUrl.trim(),
        targetBrand: targetBrand.trim() || undefined,
        noticeType,
        customNotes: customNotes.trim() || undefined,
        autoDispatch: false
      });

      showToast('success', 'Takedown Notice Drafted', `Tracking Number: ${notice.trackingNumber}`);
      setShowCreateModal(false);
      setTargetUrl('');
      setTargetBrand('');
      setCustomNotes('');
      fetchNotices();
      setSelectedNotice(notice);
    } catch (err: any) {
      showToast('error', 'Creation Failed', err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUpdateStatus = async (id: string, newStatus: TakedownStatus) => {
    try {
      const updated = await api.updateTakedownStatus(id, newStatus);
      showToast('success', 'Status Updated', `Notice is now ${newStatus}`);
      setSelectedNotice(updated);
      setNotices(prev => prev.map(n => (n.id === id ? updated : n)));
    } catch (err: any) {
      showToast('error', 'Status Update Failed', err.message);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    showToast('info', 'Copied to Clipboard', 'Notice payload copied.');
  };

  const getStatusBadge = (status: TakedownStatus) => {
    switch (status) {
      case 'DOMAIN_SUSPENDED':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> Suspended</span>;
      case 'DISPATCHED':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1"><Send className="w-3 h-3" /> Dispatched</span>;
      case 'ACKNOWLEDGED':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 flex items-center gap-1"><Clock className="w-3 h-3" /> Acknowledged</span>;
      case 'REJECTED':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1"><Ban className="w-3 h-3" /> Rejected</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center gap-1"><FileText className="w-3 h-3" /> Drafted</span>;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8 space-y-8">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-gradient-to-tr from-amber-500 to-rose-600 rounded-xl shadow-lg shadow-amber-500/20">
              <Gavel className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Legal Takedown & RFC 2142 Abuse Center</h1>
              <p className="text-xs text-slate-400 font-mono">Autonomous registrar notification, ICANN URS disputes, and DNS sinkhole enforcement</p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => fetchNotices()}
            className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
            title="Refresh list"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-amber-500 to-rose-600 hover:from-amber-400 hover:to-rose-500 text-white font-semibold text-xs shadow-lg shadow-amber-500/20 flex items-center space-x-2 transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Draft New Notice</span>
          </button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center space-x-2 overflow-x-auto pb-2">
        {['', 'DRAFTED', 'DISPATCHED', 'ACKNOWLEDGED', 'DOMAIN_SUSPENDED', 'REJECTED'].map(st => (
          <button
            key={st}
            onClick={() => setStatusFilter(st)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
              statusFilter === st
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                : 'bg-slate-900/60 text-slate-400 border border-slate-800 hover:bg-slate-800 hover:text-white'
            }`}
          >
            {st || 'All Notices'}
          </button>
        ))}
      </div>

      {/* Main Grid: List on Left, Preview on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left List */}
        <div className="lg:col-span-5 space-y-3">
          {loading ? (
            <div className="p-8 text-center text-slate-500 font-mono text-xs">Loading takedown requests...</div>
          ) : notices.length === 0 ? (
            <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-2xl border border-slate-800">
              No takedown notices found for selected filter.
            </div>
          ) : (
            notices.map(n => (
              <div
                key={n.id}
                onClick={() => setSelectedNotice(n)}
                className={`p-4 rounded-2xl border transition-all cursor-pointer ${
                  selectedNotice?.id === n.id
                    ? 'bg-slate-900/90 border-amber-500/40 shadow-lg shadow-amber-500/10'
                    : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/70 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono text-amber-400 font-bold">{n.trackingNumber}</span>
                    <h3 className="text-xs font-bold text-white truncate max-w-xs">{n.targetDomain}</h3>
                    <p className="text-[11px] text-slate-400 truncate">{n.recipientEntity}</p>
                  </div>
                  {getStatusBadge(n.status)}
                </div>
                <div className="mt-3 flex items-center justify-between text-[10px] text-slate-500 font-mono border-t border-slate-800/50 pt-2">
                  <span>{n.noticeType.replace(/_/g, ' ')}</span>
                  <span>{new Date(n.createdAt).toLocaleDateString()}</span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Right Preview Drawer */}
        <div className="lg:col-span-7">
          {selectedNotice ? (
            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 space-y-6 backdrop-blur-xl">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-bold text-amber-400">{selectedNotice.trackingNumber}</span>
                    {getStatusBadge(selectedNotice.status)}
                  </div>
                  <h2 className="text-base font-bold text-white mt-1">{selectedNotice.targetDomain}</h2>
                  <p className="text-xs text-slate-400">Targeted Brand: <strong className="text-slate-200">{selectedNotice.targetBrand || 'N/A'}</strong></p>
                </div>

                <div className="flex items-center space-x-2">
                  {selectedNotice.status === 'DRAFTED' && (
                    <button
                      onClick={() => handleUpdateStatus(selectedNotice.id, 'DISPATCHED')}
                      className="px-3.5 py-1.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-md shadow-cyan-500/20 flex items-center space-x-1.5 transition-colors"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>Dispatch Notice</span>
                    </button>
                  )}
                  {selectedNotice.status === 'DISPATCHED' && (
                    <button
                      onClick={() => handleUpdateStatus(selectedNotice.id, 'DOMAIN_SUSPENDED')}
                      className="px-3.5 py-1.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs shadow-md shadow-emerald-500/20 flex items-center space-x-1.5 transition-colors"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Mark Suspended</span>
                    </button>
                  )}
                  <button
                    onClick={() => copyToClipboard(selectedNotice.bodyText)}
                    className="p-2 rounded-xl bg-slate-800 border border-slate-700 text-slate-300 hover:text-white transition-colors"
                    title="Copy full notice text"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Destination Contact Bar */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-950/80 p-4 rounded-xl border border-slate-800">
                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-mono text-slate-500">Registrar Abuse Desk</span>
                  <div className="text-xs text-slate-200 font-semibold flex items-center gap-1.5">
                    <Mail className="w-3.5 h-3.5 text-amber-400" />
                    <span>{selectedNotice.recipientEmail}</span>
                  </div>
                </div>
                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-mono text-slate-500">Infringing Resource</span>
                  <div className="text-xs text-rose-400 font-mono truncate">{selectedNotice.targetUrl}</div>
                </div>
              </div>

              {/* Forensic Evidence Items */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Attached Zero-Trust Evidence</h4>
                <div className="space-y-1.5">
                  {selectedNotice.evidenceSummary.map((ev, i) => (
                    <div key={i} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 flex items-center space-x-2">
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                      <span>{ev}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Full Notice Text */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Transmitted RFC 2142 Legal Text</h4>
                <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 whitespace-pre-wrap max-h-72 overflow-y-auto leading-relaxed">
                  {selectedNotice.bodyText}
                </pre>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-slate-500 bg-slate-900/40 rounded-2xl border border-slate-800">
              Select a takedown notice from the list to preview legal text and abuse desk details.
            </div>
          )}
        </div>
      </div>

      {/* Modal: Draft Notice */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-in fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Gavel className="w-5 h-5 text-amber-400" />
                <span>Draft Takedown Notice</span>
              </h3>
              <button onClick={() => setShowCreateModal(false)} className="text-slate-500 hover:text-white">✕</button>
            </div>

            <form onSubmit={handleCreateNotice} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-slate-300 mb-1">Target Malicious URL *</label>
                <input
                  type="text"
                  required
                  placeholder="https://phishing-portal.example/login"
                  value={targetUrl}
                  onChange={e => setTargetUrl(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-bold text-slate-300 mb-1">Targeted Brand</label>
                  <input
                    type="text"
                    placeholder="e.g. Microsoft, PayPal"
                    value={targetBrand}
                    onChange={e => setTargetBrand(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-amber-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-300 mb-1">Notice Framework</label>
                  <select
                    value={noticeType}
                    onChange={e => setNoticeType(e.target.value as TakedownNoticeType)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-amber-500"
                  >
                    <option value="RFC2142_ABUSE_NOTICE">RFC 2142 Abuse Mailbox</option>
                    <option value="TRADEMARK_INFRINGEMENT">Trademark Infringement</option>
                    <option value="ICANN_URS_COMPLAINT">ICANN URS Complaint</option>
                    <option value="DMCA_512C_TAKEDOWN">DMCA 512(c) Notice</option>
                    <option value="REGISTRAR_SUSPENSION_REQUEST">Registrar Suspension</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-300 mb-1">Analyst Forensic Notes</label>
                <textarea
                  rows={3}
                  placeholder="Observed credential harvesting parameters or malware drop URLs..."
                  value={customNotes}
                  onChange={e => setCustomNotes(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs shadow-lg shadow-amber-500/20 flex items-center space-x-1.5 transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  <span>{isSubmitting ? 'Generating...' : 'Create Legal Notice'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
