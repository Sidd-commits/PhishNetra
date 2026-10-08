import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { CommunityReport, ReportType, ReportStatus, CreateReportRequest } from '@phishnetra/shared';
import {
  ShieldAlert,
  Plus,
  Filter,
  CheckCircle,
  XCircle,
  AlertCircle,
  MessageSquare,
  Globe,
  Activity,
  RotateCcw,
  Check,
  Ban,
  HelpCircle
} from 'lucide-react';

export const ReportsPage: React.FC = () => {
  const { user } = useAuth();
  const [reports, setReports] = useState<CommunityReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>('');

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [formUrl, setFormUrl] = useState('');
  const [formType, setFormType] = useState<ReportType>('PHISHING');
  const [formDescription, setFormDescription] = useState('');
  const [formEvidence, setFormEvidence] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Moderation State
  const [moderatingId, setModeratingId] = useState<string | null>(null);
  const [moderatorNotes, setModeratorNotes] = useState('');

  useEffect(() => {
    loadReports();
  }, [selectedStatus, selectedType]);

  const loadReports = async () => {
    setLoading(true);
    try {
      const data = await api.listReports({
        status: selectedStatus || undefined,
        reportType: selectedType || undefined,
        limit: 50
      });
      setReports(data.reports);
    } catch (err: any) {
      console.error('Failed to load reports:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!formUrl.trim() || !formDescription.trim()) {
      setFormError('URL and context description are required.');
      return;
    }

    setIsSubmitting(true);
    try {
      await api.createReport({
        url: formUrl.trim(),
        reportType: formType,
        description: formDescription.trim(),
        evidenceDetails: formEvidence.trim() || undefined
      });
      setIsModalOpen(false);
      setFormUrl('');
      setFormDescription('');
      setFormEvidence('');
      loadReports();
    } catch (err: any) {
      setFormError(err.response?.data?.message || err.message || 'Failed to submit report.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleModerate = async (reportId: string, status: ReportStatus) => {
    try {
      await api.moderateReport(reportId, {
        status,
        moderatorNotes: moderatorNotes.trim() || undefined
      });
      setModeratingId(null);
      setModeratorNotes('');
      loadReports();
    } catch (err: any) {
      console.error('Moderation error:', err);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'APPROVED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">CONFIRMED THREAT</span>;
      case 'REJECTED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400 border border-slate-700">REJECTED</span>;
      case 'RESOLVED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">RESOLVED</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30 animate-pulse">PENDING REVIEW</span>;
    }
  };

  const getTypeBadge = (type: string) => {
    switch (type) {
      case 'PHISHING':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">PHISHING</span>;
      case 'CREDENTIAL_HARVEST':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-500/10 text-orange-400 border border-orange-500/20">CREDENTIAL HARVEST</span>;
      case 'MALWARE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/10 text-purple-400 border border-purple-500/20">MALWARE</span>;
      case 'FALSE_POSITIVE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">FALSE POSITIVE</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400">SCAM</span>;
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Community Threat & Intelligence Reports</h1>
            <p className="text-sm text-slate-400">
              Crowdsourced phishing indicators, false-positive remediation, and SOC analyst moderation hub.
            </p>
          </div>
        </div>

        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-amber-500 to-rose-600 hover:from-amber-400 hover:to-rose-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-amber-500/20 transition-all self-start md:self-auto"
        >
          <Plus className="w-4 h-4" />
          <span>Submit Threat Report</span>
        </button>
      </div>

      {/* Filter Tabs & Search */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/60 border border-slate-800 p-3 rounded-xl">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setSelectedStatus('')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              selectedStatus === '' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Reports
          </button>
          <button
            onClick={() => setSelectedStatus('PENDING')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              selectedStatus === 'PENDING' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Pending Review
          </button>
          <button
            onClick={() => setSelectedStatus('APPROVED')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              selectedStatus === 'APPROVED' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Confirmed Threats
          </button>
        </div>

        <button onClick={loadReports} className="text-slate-400 hover:text-slate-200 p-1.5 rounded hover:bg-slate-800 transition-colors">
          <RotateCcw className="w-4 h-4" />
        </button>
      </div>

      {/* Reports Feed */}
      <div className="space-y-4">
        {loading ? (
          <div className="p-12 text-center text-slate-500 flex items-center justify-center space-x-2">
            <Activity className="w-5 h-5 animate-spin text-amber-400" />
            <span>Loading threat intelligence reports...</span>
          </div>
        ) : reports.length === 0 ? (
          <div className="p-12 bg-slate-900/40 border border-slate-800/80 rounded-xl text-center text-slate-500">
            No community reports found matching the selected criteria.
          </div>
        ) : (
          reports.map((report) => (
            <div
              key={report.id}
              className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3 hover:border-slate-700 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-3">
                <div className="flex items-center space-x-3">
                  {getTypeBadge(report.reportType)}
                  <span className="text-sm font-bold font-mono text-white truncate max-w-[320px] sm:max-w-md">
                    {report.url}
                  </span>
                </div>
                <div className="flex items-center space-x-3">
                  {getStatusBadge(report.status)}
                  <span className="text-xs text-slate-500 font-mono">
                    {new Date(report.createdAt).toLocaleDateString()}
                  </span>
                </div>
              </div>

              <div className="text-xs text-slate-300 leading-relaxed">
                {report.description}
              </div>

              {report.evidenceDetails && (
                <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs font-mono text-slate-400">
                  <span className="text-slate-500 block text-[10px] uppercase font-semibold mb-1">Evidence Details</span>
                  {report.evidenceDetails}
                </div>
              )}

              {report.moderatorNotes && (
                <div className="p-3 bg-indigo-950/20 border border-indigo-900/30 rounded-lg text-xs text-indigo-300 flex items-start space-x-2">
                  <MessageSquare className="w-4 h-4 shrink-0 mt-0.5 text-indigo-400" />
                  <div>
                    <span className="font-semibold block text-[10px] uppercase">SOC Analyst Assessment ({report.moderatedBy})</span>
                    {report.moderatorNotes}
                  </div>
                </div>
              )}

              {/* Moderation Controls (Analyst / Admin / Logged-in User) */}
              <div className="pt-2 flex items-center justify-between border-t border-slate-800/40">
                <span className="text-[11px] text-slate-500">
                  Reported by <span className="text-slate-300">{report.userName || 'Anonymous'}</span> • Domain: <span className="font-mono text-slate-400">{report.domain}</span>
                </span>

                <div className="flex items-center space-x-2">
                  {report.status === 'PENDING' && (
                    <>
                      <button
                        onClick={() => handleModerate(report.id, 'APPROVED')}
                        className="flex items-center space-x-1 px-2.5 py-1 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 rounded text-[11px] font-medium border border-rose-500/30 transition-colors"
                      >
                        <Check className="w-3 h-3" />
                        <span>Confirm Phishing</span>
                      </button>
                      <button
                        onClick={() => handleModerate(report.id, 'REJECTED')}
                        className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] font-medium border border-slate-700 transition-colors"
                      >
                        <Ban className="w-3 h-3" />
                        <span>Reject</span>
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Submission Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="w-5 h-5 text-amber-400" />
                <h3 className="text-base font-bold text-white">Submit Threat Report</h3>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                ×
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs text-rose-300 flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{formError}</span>
              </div>
            )}

            <form onSubmit={handleCreateReport} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-medium">Target URL / Domain:</label>
                <input
                  type="text"
                  required
                  value={formUrl}
                  onChange={(e) => setFormUrl(e.target.value)}
                  placeholder="https://malicious-login-paypal.com/signin"
                  className="w-full bg-slate-950 border border-slate-800 focus:border-amber-500 focus:ring-1 focus:ring-amber-500 rounded-lg p-2.5 text-slate-200 font-mono focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Report Classification:</label>
                <select
                  value={formType}
                  onChange={(e) => setFormType(e.target.value as ReportType)}
                  className="w-full bg-slate-950 border border-slate-800 focus:border-amber-500 focus:ring-1 focus:ring-amber-500 rounded-lg p-2.5 text-slate-200 focus:outline-none"
                >
                  <option value="PHISHING">Phishing / Brand Impersonation</option>
                  <option value="CREDENTIAL_HARVEST">Credential Harvesting Form</option>
                  <option value="MALWARE">Malware / Malicious Download</option>
                  <option value="SCAM">Scam / Financial Fraud</option>
                  <option value="FALSE_POSITIVE">False Positive Remediation</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Context & Reason for Report:</label>
                <textarea
                  required
                  rows={3}
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  placeholder="Describe suspicious behavior (e.g. unsolicited SMS lure claiming bank account lockup asking for credit card details)..."
                  className="w-full bg-slate-950 border border-slate-800 focus:border-amber-500 focus:ring-1 focus:ring-amber-500 rounded-lg p-2.5 text-slate-200 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Technical Evidence (Optional):</label>
                <textarea
                  rows={2}
                  value={formEvidence}
                  onChange={(e) => setFormEvidence(e.target.value)}
                  placeholder="Headers, form action destination, sender address, or IOC details..."
                  className="w-full bg-slate-950 border border-slate-800 focus:border-amber-500 focus:ring-1 focus:ring-amber-500 rounded-lg p-2.5 text-slate-200 font-mono focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-gradient-to-r from-amber-500 to-rose-600 hover:from-amber-400 hover:to-rose-500 text-white font-semibold rounded-lg shadow-md shadow-amber-500/20 disabled:opacity-50"
                >
                  {isSubmitting ? 'Submitting...' : 'Submit Report'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
