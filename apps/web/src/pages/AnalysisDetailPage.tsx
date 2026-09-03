import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { AnalysisResponse } from '@phishnetra/shared';
import { ScoreGauge } from '../components/ScoreGauge';
import { EvidenceTable } from '../components/EvidenceTable';
import { FeaturesTable } from '../components/FeaturesTable';
import {
  ArrowLeft,
  Search,
  Activity,
  AlertCircle,
  Clock,
  Lock,
  Globe
} from 'lucide-react';

export const AnalysisDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

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

  if (isLoading) {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center text-slate-400 space-y-3">
        <Activity className="w-8 h-8 text-cyan-400 animate-spin" />
        <p className="text-xs font-mono">Retrieving analysis report #{id?.slice(0, 8)}...</p>
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
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Top Navigation & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <button
          onClick={() => navigate(-1)}
          className="inline-flex items-center space-x-2 text-xs font-semibold text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Feed</span>
        </button>

        <div className="flex items-center space-x-3">
          <Link
            to="/analyze"
            className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
          >
            <Search className="w-3.5 h-3.5 text-cyan-400" />
            <span>Scan Another URL</span>
          </Link>
        </div>
      </div>

      {/* Target URL Inspection Card */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
          <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400">
            <Globe className="w-4 h-4" />
            <span>ANALYSIS REPORT #{analysis.analysisId}</span>
          </div>
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
            <Clock className="w-3.5 h-3.5" />
            <span>{new Date(analysis.createdAt).toLocaleString()}</span>
          </div>
        </div>

        <div className="space-y-1">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Canonical Target URL
          </span>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/90 font-mono text-sm sm:text-base text-slate-100 break-all select-all">
            {analysis.normalizedUrl}
          </div>
        </div>
      </div>

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
              Detection Telemetry & Verdict Breakdown
            </h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              PhishNetra evaluated this target through the Zero-Trust Milestone 1 pipeline, combining deterministic lexical feature extraction with a baseline machine learning classifier.
            </p>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-2">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono">Verdict</span>
                <div className="text-sm font-bold font-mono text-white mt-0.5">
                  {analysis.verdict}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono">ML Probability</span>
                <div className="text-sm font-bold font-mono text-cyan-300 mt-0.5">
                  {(analysis.mlProbability * 100).toFixed(1)}%
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono">Signals Triggered</span>
                <div className="text-sm font-bold font-mono text-amber-400 mt-0.5">
                  {analysis.evidence.length} Rules
                </div>
              </div>
            </div>
          </div>

          {/* SSRF & Security Architecture Notice */}
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-[11px] text-slate-400 flex items-start space-x-2.5">
            <Lock className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
            <span>
              <strong>SSRF-Safe URL Isolation:</strong> Milestone 1 evaluates static URL lexical semantics. Unrestricted server-side HTTP fetching is intentionally deferred to the Milestone 3 sandboxed analyzer.
            </span>
          </div>
        </div>
      </div>

      {/* Triggered Evidence Table */}
      <div className="space-y-3">
        <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
          Triggered Risk Evidence & Analyst Explanations
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
