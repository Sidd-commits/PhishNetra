import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  Settings,
  Flag,
  CheckCircle2,
  Lock,
  Globe,
  Database,
  Cpu,
  Eye,
  Info
} from 'lucide-react';
import { AnalysisResponse, ThreatVerdict } from '@phishnetra/shared';
import { LocalHeuristicResult } from '../background/localHeuristics';

interface TabStatusResponse {
  success: boolean;
  state?: {
    url: string;
    domain: string;
    localHeuristics: LocalHeuristicResult;
    analysis: AnalysisResponse | null;
    status: ThreatVerdict | 'PENDING' | 'WHITELISTED' | 'BYPASSED';
    error?: string;
    analyzedAt: number;
  };
  isWhitelisted?: boolean;
  isBypassed?: boolean;
  url?: string;
  error?: string;
}

export const PopupApp: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [tabData, setTabData] = useState<TabStatusResponse | null>(null);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportCategory, setReportCategory] = useState<'PHISHING' | 'CREDENTIAL_HARVEST' | 'MALWARE' | 'SCAM'>('PHISHING');
  const [reportNotes, setReportNotes] = useState('');
  const [reportSubmitting, setReportSubmitting] = useState(false);
  const [reportSuccess, setReportSuccess] = useState(false);

  const fetchCurrentTabStatus = () => {
    if (typeof chrome === 'undefined' || !chrome.runtime) {
      setLoading(false);
      return;
    }

    chrome.runtime.sendMessage({ type: 'GET_CURRENT_TAB_STATUS' }, (response: TabStatusResponse) => {
      setTabData(response);
      setLoading(false);
      setRefreshing(false);
    });
  };

  useEffect(() => {
    fetchCurrentTabStatus();
  }, []);

  const handleRescan = () => {
    setRefreshing(true);
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ type: 'RESCAN_URL' }, () => {
        setTimeout(fetchCurrentTabStatus, 1500);
      });
    }
  };

  const handleWhitelist = () => {
    if (!tabData?.state?.domain) return;
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'WHITELIST_DOMAIN',
        domain: tabData.state.domain
      }, () => {
        fetchCurrentTabStatus();
      });
    }
  };

  const handleOpenOptions = () => {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  };

  const handleOpenDashboard = () => {
    const targetUrl = tabData?.state?.url || tabData?.url;
    if (!targetUrl) return;
    const dashboardUrl = `http://localhost:5173/analysis?url=${encodeURIComponent(targetUrl)}`;
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url: dashboardUrl });
    } else {
      window.open(dashboardUrl, '_blank');
    }
  };

  const handleSendReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setReportSubmitting(true);
    const targetUrl = tabData?.state?.url || tabData?.url || '';

    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'REPORT_THREAT',
        targetUrl,
        category: reportCategory,
        description: reportNotes || 'Community threat reported via PhishNetra Extension popup',
        evidence: tabData?.state?.analysis || { localHeuristics: tabData?.state?.localHeuristics }
      }, (res: any) => {
        setReportSubmitting(false);
        if (res?.success) {
          setReportSuccess(true);
          setTimeout(() => {
            setReportSuccess(false);
            setReportModalOpen(false);
          }, 1800);
        }
      });
    }
  };

  if (loading) {
    return (
      <div style={{ padding: 24, textAlign: 'center', background: '#0b0f19', color: '#9ca3af', minHeight: 400 }}>
        <RefreshCw size={28} className="animate-spin" style={{ margin: '40px auto 16px', color: '#3b82f6' }} />
        <div style={{ fontSize: 13, fontWeight: 600 }}>Inspecting Security Posture...</div>
        <div style={{ fontSize: 11, color: '#6b7280', marginTop: 4 }}>Connecting to PhishNetra Core Engine</div>
      </div>
    );
  }

  const state = tabData?.state;
  const analysis = state?.analysis;
  const localHeuristics = state?.localHeuristics;
  const isWhitelisted = tabData?.isWhitelisted;
  const isBypassed = tabData?.isBypassed;

  const riskScore = analysis ? Math.round(analysis.riskScore) : (localHeuristics ? Math.round(localHeuristics.score) : 0);
  const verdict = isWhitelisted ? 'SAFE' : (analysis ? analysis.verdict : (localHeuristics?.isLikelyPhishing ? 'PHISHING' : (localHeuristics?.isSuspicious ? 'SUSPICIOUS' : 'SAFE')));

  const getStatusBadge = () => {
    if (isWhitelisted) {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '3px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700 }}>
          <CheckCircle2 size={12} /> WHITELISTED
        </span>
      );
    }
    if (isBypassed) {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: 'rgba(107, 114, 128, 0.2)', color: '#9ca3af', padding: '3px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700 }}>
          <Lock size={12} /> BYPASSED
        </span>
      );
    }
    if (verdict === 'PHISHING' || riskScore >= 75) {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', padding: '3px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700 }}>
          <ShieldAlert size={12} /> PHISHING THREAT
        </span>
      );
    }
    if (verdict === 'SUSPICIOUS' || riskScore >= 40) {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: 'rgba(245, 158, 11, 0.2)', color: '#fbbf24', padding: '3px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700 }}>
          <AlertTriangle size={12} /> SUSPICIOUS
        </span>
      );
    }
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '3px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700 }}>
        <ShieldCheck size={12} /> DOMAIN SAFE
      </span>
    );
  };

  const getScoreColor = (score: number) => {
    if (isWhitelisted) return '#10b981';
    if (score >= 75) return '#ef4444';
    if (score >= 40) return '#f59e0b';
    return '#10b981';
  };

  return (
    <div style={{ background: '#0b0f19', color: '#f3f4f6', minHeight: 520, display: 'flex', flexDirection: 'column', boxSizing: 'border-box' }}>
      {/* Top Header */}
      <div style={{ padding: '14px 16px', background: '#111827', borderBottom: '1px solid #1f2937', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ background: 'linear-gradient(135deg, #2563eb, #1d4ed8)', padding: 6, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={16} color="#ffffff" />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 800, letterSpacing: '-0.01em', color: '#f9fafb' }}>
              PhishNetra <span style={{ color: '#60a5fa', fontSize: 11, fontWeight: 600 }}>SOC</span>
            </div>
            <div style={{ fontSize: 10, color: '#9ca3af' }}>v0.5.0 • Live Defense</div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <button
            onClick={handleRescan}
            title="Rescan Page"
            disabled={refreshing}
            style={{ background: 'transparent', border: 'none', color: '#9ca3af', cursor: 'pointer', padding: 5, borderRadius: 4, display: 'flex', alignItems: 'center' }}
          >
            <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
          </button>
          <button
            onClick={handleOpenOptions}
            title="Settings & Whitelist"
            style={{ background: 'transparent', border: 'none', color: '#9ca3af', cursor: 'pointer', padding: 5, borderRadius: 4, display: 'flex', alignItems: 'center' }}
          >
            <Settings size={14} />
          </button>
        </div>
      </div>

      {/* Target Domain Bar */}
      <div style={{ padding: '10px 16px', background: '#131c2e', borderBottom: '1px solid #1e293b', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 220 }}>
          <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Target Domain</div>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#93c5fd', fontFamily: 'monospace' }}>
            {state?.domain || 'Unknown Domain'}
          </div>
        </div>
        <div>
          {getStatusBadge()}
        </div>
      </div>

      {/* Main Body Content */}
      <div style={{ padding: 16, flex: 1, overflowY: 'auto' }}>
        {/* Risk Score Gauge Card */}
        <div style={{
          background: 'rgba(17, 24, 39, 0.7)',
          border: `1px solid ${getScoreColor(riskScore)}40`,
          borderRadius: 12,
          padding: 16,
          marginBottom: 14,
          textAlign: 'center'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#9ca3af', textTransform: 'uppercase' }}>Composite Threat Rating</span>
            <span style={{ fontSize: 11, fontWeight: 600, color: getScoreColor(riskScore) }}>
              {isWhitelisted ? '0% Risk' : `${riskScore}/100 Score`}
            </span>
          </div>

          <div style={{ height: 8, width: '100%', background: '#1f2937', borderRadius: 4, overflow: 'hidden', marginBottom: 12 }}>
            <div style={{
              height: '100%',
              width: `${isWhitelisted ? 5 : Math.max(5, riskScore)}%`,
              background: getScoreColor(riskScore),
              transition: 'width 0.4s ease'
            }} />
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-around', borderTop: '1px solid #1f2937', paddingTop: 10 }}>
            <div>
              <div style={{ fontSize: 9, color: '#6b7280', textTransform: 'uppercase' }}>Entropy</div>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#e5e7eb' }}>
                {localHeuristics?.entropy || '0.00'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: '#6b7280', textTransform: 'uppercase' }}>AI Confidence</div>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#e5e7eb' }}>
                {analysis ? `${Math.round((analysis.mlProbability || analysis.confidence || 0.95) * 100)}%` : 'N/A'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: '#6b7280', textTransform: 'uppercase' }}>Verdict</div>
              <div style={{ fontSize: 12, fontWeight: 800, color: getScoreColor(riskScore) }}>
                {verdict}
              </div>
            </div>
          </div>
        </div>

        {/* Multi-Layer Intelligence Grid */}
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#9ca3af', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.05em' }}>
            Multi-Tier Inspection Layers
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {/* Layer 1: Lexical */}
            <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, padding: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <Globe size={12} color="#60a5fa" />
                <span style={{ fontSize: 11, fontWeight: 600, color: '#d1d5db' }}>Lexical / URL</span>
              </div>
              <div style={{ fontSize: 11, color: localHeuristics?.isSuspicious ? '#f59e0b' : '#10b981', fontWeight: 700 }}>
                {localHeuristics?.isLikelyPhishing ? 'High Risk' : (localHeuristics?.isSuspicious ? 'Suspicious' : 'Clean')}
              </div>
            </div>

            {/* Layer 2: Domain Age & RDAP */}
            <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, padding: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <Database size={12} color="#a78bfa" />
                <span style={{ fontSize: 11, fontWeight: 600, color: '#d1d5db' }}>RDAP / Age</span>
              </div>
              <div style={{ fontSize: 11, color: analysis?.layers?.domain?.domainAgeDays && analysis.layers.domain.domainAgeDays < 30 ? '#f59e0b' : '#9ca3af', fontWeight: 700 }}>
                {analysis?.layers?.domain?.domainAgeDays !== undefined && analysis.layers.domain.domainAgeDays !== null ? `${analysis.layers.domain.domainAgeDays}d old` : 'Verified'}
              </div>
            </div>

            {/* Layer 3: Sandbox DOM */}
            <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, padding: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <Eye size={12} color="#34d399" />
                <span style={{ fontSize: 11, fontWeight: 600, color: '#d1d5db' }}>DOM Harvest</span>
              </div>
              <div style={{ fontSize: 11, color: analysis?.pageAnalysis?.forms?.some((f) => f.hasPasswordField) ? '#ef4444' : '#10b981', fontWeight: 700 }}>
                {analysis?.pageAnalysis?.forms?.some((f) => f.hasPasswordField) ? 'Password Form' : 'No Threat'}
              </div>
            </div>

            {/* Layer 4: AI Model */}
            <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, padding: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <Cpu size={12} color="#f472b6" />
                <span style={{ fontSize: 11, fontWeight: 600, color: '#d1d5db' }}>AI Pipeline</span>
              </div>
              <div style={{ fontSize: 11, color: analysis?.mlProbability && analysis.mlProbability > 0.5 ? '#ef4444' : '#10b981', fontWeight: 700 }}>
                {analysis ? (analysis.mlProbability > 0.5 ? 'Malicious' : 'Benign') : 'Active'}
              </div>
            </div>
          </div>
        </div>

        {/* Threat Reasons / Flags */}
        {localHeuristics?.reasons && localHeuristics.reasons.length > 0 && (
          <div style={{ background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: 8, padding: 10, marginBottom: 14 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#f87171', textTransform: 'uppercase', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 4 }}>
              <Info size={11} /> Flagged Heuristics
            </div>
            <ul style={{ margin: 0, paddingLeft: 14, fontSize: 11, color: '#fca5a5', lineHeight: 1.4 }}>
              {localHeuristics.reasons.map((r, i) => (
                <li key={i} style={{ marginBottom: 2 }}>{r}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Footer SOC Quick Actions */}
      <div style={{ padding: 12, background: '#111827', borderTop: '1px solid #1f2937', display: 'flex', gap: 8 }}>
        <button
          onClick={handleOpenDashboard}
          style={{
            flex: 1,
            background: '#2563eb',
            color: '#ffffff',
            border: 'none',
            borderRadius: 6,
            padding: '8px 10px',
            fontSize: 12,
            fontWeight: 700,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 6
          }}
        >
          <ExternalLink size={13} /> Inspect Dossier
        </button>

        <button
          onClick={() => setReportModalOpen(true)}
          title="Report Phishing"
          style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid #ef4444',
            color: '#f87171',
            borderRadius: 6,
            padding: '8px 10px',
            fontSize: 12,
            fontWeight: 700,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 4
          }}
        >
          <Flag size={13} /> Report
        </button>

        {!isWhitelisted && (
          <button
            onClick={handleWhitelist}
            title="Whitelist Domain"
            style={{
              background: '#1f2937',
              border: '1px solid #374151',
              color: '#d1d5db',
              borderRadius: 6,
              padding: '8px 10px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Trust
          </button>
        )}
      </div>

      {/* Community Report Modal */}
      {reportModalOpen && (
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          background: 'rgba(11, 15, 25, 0.95)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          padding: 20,
          boxSizing: 'border-box',
          zIndex: 100
        }}>
          {reportSuccess ? (
            <div style={{ textAlign: 'center', color: '#34d399' }}>
              <CheckCircle2 size={36} style={{ margin: '0 auto 12px' }} />
              <div style={{ fontSize: 14, fontWeight: 700 }}>Report Submitted!</div>
              <div style={{ fontSize: 11, color: '#9ca3af', marginTop: 4 }}>Queued for PhishNetra SOC Moderation</div>
            </div>
          ) : (
            <form onSubmit={handleSendReport}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#f3f4f6', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Flag size={14} color="#ef4444" /> Report Threat to SOC
                </div>
                <button
                  type="button"
                  onClick={() => setReportModalOpen(false)}
                  style={{ background: 'transparent', border: 'none', color: '#9ca3af', cursor: 'pointer', fontSize: 16 }}
                >
                  ✕
                </button>
              </div>

              <div style={{ marginBottom: 10 }}>
                <label style={{ fontSize: 10, color: '#9ca3af', textTransform: 'uppercase', display: 'block', marginBottom: 4 }}>Threat Category</label>
                <select
                  value={reportCategory}
                  onChange={(e: any) => setReportCategory(e.target.value)}
                  style={{ width: '100%', background: '#1f2937', border: '1px solid #374151', color: '#f3f4f6', padding: '6px 8px', borderRadius: 4, fontSize: 12 }}
                >
                  <option value="PHISHING">Phishing / Brand Impersonation</option>
                  <option value="CREDENTIAL_HARVEST">Credential Harvester</option>
                  <option value="MALWARE">Malware / Malicious Download</option>
                  <option value="SCAM">Cryptocurrency / Financial Scam</option>
                </select>
              </div>

              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 10, color: '#9ca3af', textTransform: 'uppercase', display: 'block', marginBottom: 4 }}>Analyst Notes (Optional)</label>
                <textarea
                  value={reportNotes}
                  onChange={(e) => setReportNotes(e.target.value)}
                  placeholder="Describe suspicious behavior or harvested brand..."
                  rows={3}
                  style={{ width: '100%', background: '#1f2937', border: '1px solid #374151', color: '#f3f4f6', padding: '6px 8px', borderRadius: 4, fontSize: 11, boxSizing: 'border-box', resize: 'none' }}
                />
              </div>

              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  type="submit"
                  disabled={reportSubmitting}
                  style={{ flex: 1, background: '#ef4444', color: '#ffffff', border: 'none', padding: '8px 12px', borderRadius: 4, fontSize: 12, fontWeight: 700, cursor: 'pointer' }}
                >
                  {reportSubmitting ? 'Submitting...' : 'Submit Threat Report'}
                </button>
                <button
                  type="button"
                  onClick={() => setReportModalOpen(false)}
                  style={{ background: '#374151', color: '#d1d5db', border: 'none', padding: '8px 12px', borderRadius: 4, fontSize: 12, cursor: 'pointer' }}
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </div>
  );
};
