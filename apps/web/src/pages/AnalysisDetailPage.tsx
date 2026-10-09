import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { AnalysisResponse } from '@phishnetra/shared';
import { ScoreGauge } from '../components/ScoreGauge';
import { EvidenceTable } from '../components/EvidenceTable';
import { FeaturesTable } from '../components/FeaturesTable';
import { LayersBreakdown } from '../components/LayersBreakdown';
import { PageAnalysisView } from '../components/PageAnalysisView';
import { ZeroTrustBanner } from '../components/ZeroTrustBanner';
import {
  ArrowLeft,
  Search,
  Activity,
  AlertCircle,
  Clock,
  Globe,
  Info,
  Copy,
  Check,
  Download,
  ShieldAlert,
  Zap,
  ExternalLink,
  Shield,
  FileCode,
  Crosshair
} from 'lucide-react';

export const AnalysisDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedUrl, setCopiedUrl] = useState<boolean>(false);
  const [showRpzModal, setShowRpzModal] = useState<boolean>(false);
  const [copiedRpz, setCopiedRpz] = useState<boolean>(false);

  const navigate = useNavigate();

  useEffect(() => {
    const fetchAnalysis = async () => {
      if (!id) return;
      try {
        const data = await api.getAnalysisById(id);
        setAnalysis(data);
      } catch (err: any) {
        setError(err.response?.data?.message || err.message || 'Analysis report could not be found.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchAnalysis();
  }, [id]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  const copyRpzRule = (rule: string) => {
    navigator.clipboard.writeText(rule);
    setCopiedRpz(true);
    setTimeout(() => setCopiedRpz(false), 2000);
  };

  const downloadJsonTelemetry = () => {
    if (!analysis) return;
    const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: 'application/json' });
    const blobUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = `phishnetra-forensics-${analysis.analysisId.slice(0, 8)}.json`;
    link.click();
    URL.revokeObjectURL(blobUrl);
  };

  // Derive domain from canonical URL
  const extractedDomain = (() => {
    if (!analysis) return '';
    try {
      const parsed = new URL(analysis.normalizedUrl);
      return parsed.hostname;
    } catch {
      return 'target-domain.internal';
    }
  })();

  const rpzRuleText = `; PhishNetra Zero-Trust Threat Mitigation Response Policy Zone (RPZ)
; Target Domain: ${extractedDomain}
; Triggered Verdict: ${analysis?.verdict || 'MALICIOUS'} | Risk Score: ${analysis?.riskScore || 0}/100
; Generated: ${new Date().toISOString()}

${extractedDomain}       CNAME .
*.${extractedDomain}     CNAME .
`;

  if (isLoading) {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center text-slate-400 space-y-3">
        <Activity className="w-8 h-8 text-cyan-400 animate-spin" />
        <p className="text-xs font-mono">Retrieving multi-layer threat intelligence report #{id?.slice(0, 8)}...</p>
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-16 text-center space-y-4">
        <AlertCircle className="w-12 h-12 text-rose-400 mx-auto" />
        <h2 className="text-xl font-bold text-white">Investigation Report Not Found</h2>
        <p className="text-xs text-slate-400">{error || 'The requested analysis ID does not exist.'}</p>
        <Link
          to="/dashboard"
          className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl bg-slate-800 text-cyan-300 text-xs font-semibold hover:bg-slate-700 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Return to Dashboard</span>
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 animate-fadeIn">
      {/* Top Navigation & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <button
          onClick={() => navigate(-1)}
          className="inline-flex items-center space-x-2 text-xs font-semibold text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Feed</span>
        </button>

        <div className="flex items-center space-x-2 sm:space-x-3">
          <button
            type="button"
            onClick={downloadJsonTelemetry}
            className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white text-xs font-mono transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export JSON</span>
          </button>

          <Link
            to="/analyze"
            className="inline-flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold shadow-md transition-all active:scale-[0.98]"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Analyze Another URL</span>
          </Link>
        </div>
      </div>

      {/* Zero-Trust UX Banner */}
      <ZeroTrustBanner
        hasTls={analysis.layers?.tls?.hasTls}
        verdict={analysis.verdict}
      />

      {/* Synthesized Analysis Summary Banner */}
      {analysis.summary && (
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-700/80 shadow-md">
          <div className="flex items-center space-x-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-1.5">
            <Info className="w-3.5 h-3.5" />
            <span>Threat Summary</span>
          </div>
          <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">
            {analysis.summary}
          </p>
        </div>
      )}

      {/* Target URL Inspection Card */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl border-slate-800 space-y-4 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
          <div className="flex items-center space-x-2 text-xs text-slate-300">
            <Globe className="w-4 h-4 text-cyan-400" />
            <span className="font-medium">Investigation Report #{analysis.analysisId.slice(0, 8)}</span>
          </div>
          <div className="flex items-center space-x-2 text-xs text-slate-400">
            <Clock className="w-3.5 h-3.5" />
            <span>{new Date(analysis.createdAt).toLocaleString()}</span>
          </div>
        </div>

        <div className="space-y-1.5">
          <span className="text-xs text-slate-400 font-medium">
            Canonical Target URL
          </span>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/90 font-mono text-sm sm:text-base text-slate-100 break-all flex items-center justify-between gap-3">
            <span className="select-all">{analysis.normalizedUrl}</span>
            <button
              type="button"
              onClick={() => copyToClipboard(analysis.normalizedUrl)}
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white transition-colors flex-shrink-0"
              title="Copy URL"
            >
              {copiedUrl ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Remediation Action Trigger Bar */}
        <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center space-x-1.5 text-xs text-slate-400 font-medium">
            <Zap className="w-3.5 h-3.5 text-cyan-400" />
            <span>Remediation Actions:</span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setShowRpzModal(true)}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-300 text-xs font-mono transition-colors flex items-center space-x-1.5"
            >
              <FileCode className="w-3.5 h-3.5 text-cyan-400" />
              <span>Generate RPZ Rule</span>
            </button>

            <Link
              to={`/cases`}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-amber-300 text-xs font-mono transition-colors flex items-center space-x-1.5"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              <span>Escalate Case</span>
            </Link>

            <Link
              to={`/takedowns`}
              className="px-3 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 text-xs font-mono transition-colors flex items-center space-x-1.5 font-bold"
            >
              <Crosshair className="w-3.5 h-3.5 text-rose-400" />
              <span>Dispatch Abuse Takedown</span>
            </Link>

            <Link
              to={`/rbi`}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-purple-300 text-xs font-mono transition-colors flex items-center space-x-1.5"
            >
              <ExternalLink className="w-3.5 h-3.5 text-purple-400" />
              <span>Sandbox DOM</span>
            </Link>
          </div>
        </div>
      </div>

      {/* RPZ Modal Overlay */}
      {showRpzModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div className="glass-panel p-6 rounded-2xl border-cyan-500/30 max-w-xl w-full space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-cyan-400 font-mono text-sm font-bold">
                <FileCode className="w-4 h-4" />
                <span>DNS Response Policy Zone (RPZ) Sinkhole Rule</span>
              </div>
              <button
                type="button"
                onClick={() => setShowRpzModal(false)}
                className="text-slate-400 hover:text-white text-xs font-mono px-2 py-1 rounded bg-slate-900"
              >
                ✕ Close
              </button>
            </div>

            <p className="text-xs text-slate-300">
              Apply this policy rule to your recursive resolvers (BIND9, PowerDNS, Unbound, or Infoblox) to immediately sinkhole client queries for this host:
            </p>

            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-400 overflow-x-auto select-all">
              {rpzRuleText}
            </pre>

            <div className="flex justify-end space-x-2">
              <button
                type="button"
                onClick={() => copyRpzRule(rpzRuleText)}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-1.5 transition-colors"
              >
                {copiedRpz ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedRpz ? 'Copied to Clipboard' : 'Copy RPZ Syntax'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main Score & Signal Synthesis Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Risk Gauge */}
        <div className="md:col-span-1">
          <ScoreGauge
            score={analysis.riskScore}
            verdict={analysis.verdict}
            riskLevel={analysis.riskLevel}
            confidence={analysis.confidence}
          />
        </div>

        {/* Security Summary & Engine Architecture */}
        <div className="md:col-span-2 glass-panel p-6 sm:p-8 rounded-2xl border-slate-800 flex flex-col justify-between space-y-6">
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-slate-200 font-mono uppercase tracking-wider">
              Multi-Layer Threat Engine Synthesis
            </h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              PhishNetra evaluated this target through the Zero-Trust multi-layer pipeline, independently analyzing URL lexical structure, RDAP domain age, passive DNS records, TLS certificate authenticity, and reputation threat feeds.
            </p>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono">Final Verdict</span>
                <div className="text-sm font-bold font-mono text-white mt-0.5">
                  {analysis.verdict}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono">Risk Level</span>
                <div className="text-sm font-bold font-mono text-amber-400 mt-0.5">
                  {analysis.riskLevel}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono">ML Probability</span>
                <div className="text-sm font-bold font-mono text-cyan-300 mt-0.5">
                  {(analysis.mlProbability * 100).toFixed(1)}%
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono">Triggered Evidence</span>
                <div className="text-sm font-bold font-mono text-purple-400 mt-0.5">
                  {analysis.evidence.length} Signals
                </div>
              </div>
            </div>
          </div>

          {/* Layer Health Status Row */}
          {analysis.layerStatuses && (
            <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/80">
              <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-2">
                Active Detection Layer Status
              </div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(analysis.layerStatuses).map(([layer, status]) => (
                  <span
                    key={layer}
                    className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-mono bg-slate-900 border border-slate-800"
                  >
                    <span className="text-slate-400">{layer}:</span>
                    <span className={`font-bold ${status === 'SUCCESS' ? 'text-emerald-400' : status === 'PARTIAL' ? 'text-amber-400' : 'text-slate-500'}`}>
                      {status}
                    </span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 8 Multi-Layer Breakdown Cards */}
      {analysis.layers && (
        <LayersBreakdown
          layers={analysis.layers}
          layerStatuses={analysis.layerStatuses}
        />
      )}

      {/* Secure Webpage / Content Analysis View */}
      {analysis.pageAnalysis && (
        <PageAnalysisView pageAnalysis={analysis.pageAnalysis} />
      )}

      {/* Layer-Grouped Triggered Evidence Table */}
      <div className="space-y-3">
        <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
          Triggered Risk Evidence & Layer Attribution
        </h3>
        <EvidenceTable evidence={analysis.evidence} />
      </div>

      {/* Raw Extracted Features Grid */}
      {analysis.features && (
        <div className="space-y-3">
          <FeaturesTable features={analysis.features} />
        </div>
      )}
    </div>
  );
};

