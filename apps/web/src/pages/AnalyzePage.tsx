import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { AnalysisResponse } from '@phishnetra/shared';
import { ScoreGauge } from '../components/ScoreGauge';
import { EvidenceTable } from '../components/EvidenceTable';
import {
  Search,
  ShieldAlert,
  ArrowRight,
  AlertCircle,
  Sparkles,
  Layers,
  Cpu,
  CheckCircle,
  ExternalLink
} from 'lucide-react';

export const AnalyzePage: React.FC = () => {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [analysisStep, setAnalysisStep] = useState<number>(0);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const navigate = useNavigate();

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setError(null);
    setResult(null);
    setIsLoading(true);
    setAnalysisStep(1);

    // Visual step progression
    const t1 = setTimeout(() => setAnalysisStep(2), 300);
    const t2 = setTimeout(() => setAnalysisStep(3), 650);

    try {
      const data = await api.analyzeUrl(url.trim());
      clearTimeout(t1);
      clearTimeout(t2);
      setAnalysisStep(4);
      setResult(data);
    } catch (err: any) {
      clearTimeout(t1);
      clearTimeout(t2);
      setError(
        err.response?.data?.message || err.message || 'Threat analysis failed. Please verify the URL.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const setSampleUrl = (sample: string) => {
    setUrl(sample);
    setResult(null);
    setError(null);
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Title Header */}
      <div className="text-center space-y-2 max-w-2xl mx-auto">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 text-xs font-mono mb-2">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Real-Time URL Threat Scanner</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Inspect & Analyze Target URL
        </h1>
        <p className="text-xs sm:text-sm text-slate-400">
          Enter any candidate URL to evaluate lexical signals, deterministic features, and ML probability.
        </p>
      </div>

      {/* Input Search Console */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl border-slate-800 space-y-4">
        <form onSubmit={handleAnalyze} className="space-y-4">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-cyan-400" />
            </div>
            <input
              type="text"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/login or http://192.168.1.1/secure-update"
              className="block w-full pl-12 pr-32 py-4 bg-slate-950 border border-slate-700/80 rounded-xl text-sm sm:text-base font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 transition-all shadow-inner"
            />
            <button
              type="submit"
              disabled={isLoading || !url.trim()}
              className="absolute right-2 top-2 bottom-2 px-5 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-xs sm:text-sm rounded-lg shadow-md shadow-cyan-500/20 transition-all flex items-center space-x-2 disabled:opacity-50"
            >
              {isLoading ? (
                <span>Scanning...</span>
              ) : (
                <>
                  <span>Analyze</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </form>

        {/* Quick Sample Presets */}
        <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-mono text-slate-400 mr-1">Sample Fixtures:</span>
          <button
            type="button"
            onClick={() => setSampleUrl('https://wikipedia.org/wiki/Phishing')}
            className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-emerald-400 hover:border-emerald-500/40 transition-colors"
          >
            [Safe] Wikipedia HTTPS
          </button>
          <button
            type="button"
            onClick={() => setSampleUrl('http://192.168.1.50/paypal-login-verify-account/signin.php')}
            className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-rose-400 hover:border-rose-500/40 transition-colors"
          >
            [Phishing] IP + PayPal Masquerade
          </button>
          <button
            type="button"
            onClick={() => setSampleUrl('http://paypal-verification-center.login-verify.top/index.php')}
            className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-amber-400 hover:border-amber-500/40 transition-colors"
          >
            [Suspicious] Subdomain Masquerade
          </button>
        </div>
      </div>

      {/* Error View */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-start space-x-3 text-rose-300 text-sm">
          <AlertCircle className="w-5 h-5 text-rose-400 mt-0.5 flex-shrink-0" />
          <div>
            <span className="font-bold">Analysis Error: </span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Real-Time Processing Stepper */}
      {isLoading && (
        <div className="glass-panel p-6 rounded-2xl border-slate-800 space-y-4">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-cyan-400 animate-spin" />
            <span>Execution Pipeline Progress</span>
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className={`p-3 rounded-xl border transition-all ${analysisStep >= 1 ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300' : 'bg-slate-950 border-slate-800 text-slate-500'}`}>
              <div className="flex items-center space-x-2 text-xs font-mono">
                {analysisStep > 1 ? <CheckCircle className="w-3.5 h-3.5 text-cyan-400" /> : <Layers className="w-3.5 h-3.5" />}
                <span>1. URL Canonicalization</span>
              </div>
            </div>
            <div className={`p-3 rounded-xl border transition-all ${analysisStep >= 2 ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300' : 'bg-slate-950 border-slate-800 text-slate-500'}`}>
              <div className="flex items-center space-x-2 text-xs font-mono">
                {analysisStep > 2 ? <CheckCircle className="w-3.5 h-3.5 text-cyan-400" /> : <Cpu className="w-3.5 h-3.5" />}
                <span>2. Feature Vector Extraction</span>
              </div>
            </div>
            <div className={`p-3 rounded-xl border transition-all ${analysisStep >= 3 ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300' : 'bg-slate-950 border-slate-800 text-slate-500'}`}>
              <div className="flex items-center space-x-2 text-xs font-mono">
                {analysisStep >= 4 ? <CheckCircle className="w-3.5 h-3.5 text-cyan-400" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                <span>3. ML & Risk Synthesis</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Analysis Output Presentation */}
      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Risk Gauge Card */}
            <div className="md:col-span-1">
              <ScoreGauge
                score={result.riskScore}
                verdict={result.verdict}
                riskLevel={result.riskLevel}
                confidence={result.confidence}
              />
            </div>

            {/* Overview Summary Card */}
            <div className="md:col-span-2 glass-panel p-6 rounded-2xl border-slate-800 flex flex-col justify-between space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                    Target Inspection Summary
                  </span>
                  <span className="text-xs font-mono text-cyan-400">
                    ID: {result.analysisId.slice(0, 8)}...
                  </span>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs sm:text-sm text-slate-200 break-all">
                  {result.normalizedUrl}
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-2">
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-mono">ML Probability:</span>
                    <div className="text-sm font-bold font-mono text-cyan-300">
                      {(result.mlProbability * 100).toFixed(1)}%
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-mono">Triggered Signals:</span>
                    <div className="text-sm font-bold font-mono text-slate-200">
                      {result.evidence.length} Rules
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-mono">Analysis Status:</span>
                    <div className="text-sm font-bold font-mono text-emerald-400">
                      COMPLETED
                    </div>
                  </div>
                </div>
              </div>

              {/* Action: Open Full Report */}
              <div className="pt-4 border-t border-slate-800/80 flex justify-end">
                <button
                  type="button"
                  onClick={() => navigate(`/analysis/${result.analysisId}`)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-cyan-500/20 text-slate-200 hover:text-cyan-300 text-xs font-bold transition-all flex items-center space-x-1.5"
                >
                  <span>Open Full Investigation Report</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* Evidence Details Preview */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
              Triggered Risk Evidence & Rationale
            </h3>
            <EvidenceTable evidence={result.evidence} />
          </div>
        </div>
      )}
    </div>
  );
};
