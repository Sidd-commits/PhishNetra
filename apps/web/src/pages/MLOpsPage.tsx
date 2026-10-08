import React, { useState, useEffect } from 'react';
import {
  Brain,
  Cpu,
  Layers,
  Activity,
  ShieldCheck,
  ShieldAlert,
  Zap,
  RefreshCw,
  Play,
  RotateCw,
  AlertTriangle,
  CheckCircle2,
  TrendingUp,
  BarChart2,
  Database,
  Crosshair,
  Sliders,
  Check,
  Sparkles,
  Info,
  ChevronRight,
  HelpCircle,
  Clock,
  ArrowRight
} from 'lucide-react';
import {
  SHAPExplanation,
  ModelRegistryOverview,
  ModelMetadata,
  DriftReport,
  AdversarialEvaluationReport
} from '@phishnetra/shared';
import { api } from '../services/api';

export const MLOpsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'explain' | 'models' | 'drift' | 'adversarial'>('explain');
  
  // Model Registry State
  const [registry, setRegistry] = useState<ModelRegistryOverview | null>(null);
  const [loadingModels, setLoadingModels] = useState<boolean>(true);
  const [activatingVersion, setActivatingVersion] = useState<string | null>(null);
  const [retrainAlgorithm, setRetrainAlgorithm] = useState<string>('RandomForest');
  const [autoActivateThreshold, setAutoActivateThreshold] = useState<number>(0.90);
  const [isRetraining, setIsRetraining] = useState<boolean>(false);
  const [retrainResult, setRetrainResult] = useState<any>(null);

  // SHAP Explainability State
  const [explainUrl, setExplainUrl] = useState<string>('http://192.168.1.1/login-account-update.php?token=892348');
  const [explanation, setExplanation] = useState<SHAPExplanation | null>(null);
  const [isExplaining, setIsExplaining] = useState<boolean>(false);

  // Drift Monitoring State
  const [driftReport, setDriftReport] = useState<DriftReport | null>(null);
  const [loadingDrift, setLoadingDrift] = useState<boolean>(true);
  const [customLiveBatch, setCustomLiveBatch] = useState<string>('');
  const [evaluatingDrift, setEvaluatingDrift] = useState<boolean>(false);

  // Adversarial Lab State
  const [adversarialReport, setAdversarialReport] = useState<AdversarialEvaluationReport | null>(null);
  const [loadingAdversarial, setLoadingAdversarial] = useState<boolean>(false);
  const [adversarialTestUrl, setAdversarialTestUrl] = useState<string>('http://192.168.1.100/admin-login.php');

  // Fetch initial registry & drift data
  useEffect(() => {
    fetchModelRegistry();
    fetchDriftMetrics();
  }, []);

  const fetchModelRegistry = async () => {
    try {
      setLoadingModels(true);
      const data = await api.getModelRegistry();
      setRegistry(data);
    } catch (err) {
      console.error('Failed to load model registry:', err);
    } finally {
      setLoadingModels(false);
    }
  };

  const fetchDriftMetrics = async () => {
    try {
      setLoadingDrift(true);
      const data = await api.getDriftMetrics();
      setDriftReport(data);
    } catch (err) {
      console.error('Failed to load drift report:', err);
    } finally {
      setLoadingDrift(false);
    }
  };

  const handleActivateModel = async (version: string) => {
    try {
      setActivatingVersion(version);
      await api.activateModel(version);
      await fetchModelRegistry();
    } catch (err: any) {
      alert(`Activation failed: ${err.message}`);
    } finally {
      setActivatingVersion(null);
    }
  };

  const handleRunRetrain = async () => {
    try {
      setIsRetraining(true);
      setRetrainResult(null);
      const result = await api.triggerRetraining({
        algorithm: retrainAlgorithm,
        auto_activate_threshold: autoActivateThreshold
      });
      setRetrainResult(result);
      await fetchModelRegistry();
    } catch (err: any) {
      alert(`Retraining failed: ${err.message}`);
    } finally {
      setIsRetraining(false);
    }
  };

  const handleComputeExplanation = async (targetUrl?: string) => {
    const urlToRun = targetUrl || explainUrl;
    if (!urlToRun.trim()) return;
    try {
      setIsExplaining(true);
      const data = await api.explainPrediction(urlToRun.trim());
      setExplanation(data);
    } catch (err: any) {
      alert(`Explanation computation failed: ${err.message}`);
    } finally {
      setIsExplaining(false);
    }
  };

  const handleEvaluateCustomDrift = async () => {
    const urls = customLiveBatch
      .split('\n')
      .map(u => u.trim())
      .filter(u => u.length > 3);

    try {
      setEvaluatingDrift(true);
      const data = await api.getDriftMetrics(urls.length > 0 ? urls : undefined);
      setDriftReport(data);
    } catch (err: any) {
      alert(`Drift evaluation failed: ${err.message}`);
    } finally {
      setEvaluatingDrift(false);
    }
  };

  const handleRunAdversarial = async () => {
    try {
      setLoadingAdversarial(true);
      const report = await api.runAdversarialTest({
        url: adversarialTestUrl.trim() || undefined
      });
      setAdversarialReport(report);
    } catch (err: any) {
      alert(`Adversarial test failed: ${err.message}`);
    } finally {
      setLoadingAdversarial(false);
    }
  };

  const activeModel = registry?.activeModel;

  return (
    <div className="space-y-6">
      {/* Top Header Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 backdrop-blur-md relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <span className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
                <Brain className="w-6 h-6" />
              </span>
              <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
                MLOps & Model Intelligence Console
              </h1>
            </div>
            <p className="text-slate-400 text-sm">
              Continuous model lifecycle monitoring, SHAP feature explainability, data drift tracking (PSI/KS), and adversarial robustness hardening.
            </p>
          </div>

          {/* Quick Active Model Badge */}
          {activeModel && (
            <div className="flex items-center gap-3 bg-slate-950/80 border border-cyan-500/30 px-4 py-2.5 rounded-lg shadow-lg">
              <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
              <div>
                <div className="text-xs text-slate-400 font-mono">ACTIVE INFERENCE MODEL</div>
                <div className="text-sm font-semibold text-cyan-400 font-mono">
                  {activeModel.version} <span className="text-xs text-slate-400 font-normal">({activeModel.algorithm})</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Global Key Metrics Ribbon */}
        {activeModel && (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 mt-6 pt-5 border-t border-slate-800/80">
            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
              <div className="text-[11px] text-slate-400 font-medium">Accuracy</div>
              <div className="text-lg font-bold text-emerald-400 font-mono mt-0.5">
                {(activeModel.accuracy * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
              <div className="text-[11px] text-slate-400 font-medium">Precision</div>
              <div className="text-lg font-bold text-cyan-400 font-mono mt-0.5">
                {(activeModel.precision * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
              <div className="text-[11px] text-slate-400 font-medium">Recall</div>
              <div className="text-lg font-bold text-blue-400 font-mono mt-0.5">
                {(activeModel.recall * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
              <div className="text-[11px] text-slate-400 font-medium">F1-Score</div>
              <div className="text-lg font-bold text-purple-400 font-mono mt-0.5">
                {(activeModel.f1Score * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
              <div className="text-[11px] text-slate-400 font-medium">ROC AUC</div>
              <div className="text-lg font-bold text-amber-400 font-mono mt-0.5">
                {(activeModel.rocAuc * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
              <div className="text-[11px] text-slate-400 font-medium">Dataset Samples</div>
              <div className="text-lg font-bold text-slate-200 font-mono mt-0.5">
                {activeModel.datasetSamples.toLocaleString()}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 space-x-2">
        <button
          onClick={() => setActiveTab('explain')}
          className={`flex items-center gap-2 px-4 py-3 font-medium text-sm transition-all border-b-2 -mb-px ${
            activeTab === 'explain'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/10 rounded-t-lg'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 rounded-t-lg'
          }`}
        >
          <Sparkles className="w-4 h-4" />
          SHAP Feature Attribution
        </button>

        <button
          onClick={() => setActiveTab('models')}
          className={`flex items-center gap-2 px-4 py-3 font-medium text-sm transition-all border-b-2 -mb-px ${
            activeTab === 'models'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/10 rounded-t-lg'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 rounded-t-lg'
          }`}
        >
          <Layers className="w-4 h-4" />
          Model Registry & Retraining
        </button>

        <button
          onClick={() => setActiveTab('drift')}
          className={`flex items-center gap-2 px-4 py-3 font-medium text-sm transition-all border-b-2 -mb-px ${
            activeTab === 'drift'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/10 rounded-t-lg'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 rounded-t-lg'
          }`}
        >
          <Activity className="w-4 h-4" />
          Data Drift Monitor (PSI/KS)
        </button>

        <button
          onClick={() => setActiveTab('adversarial')}
          className={`flex items-center gap-2 px-4 py-3 font-medium text-sm transition-all border-b-2 -mb-px ${
            activeTab === 'adversarial'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/10 rounded-t-lg'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 rounded-t-lg'
          }`}
        >
          <Crosshair className="w-4 h-4" />
          Adversarial Hardening Lab
        </button>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: SHAP Feature Attribution & Local Explainability                   */}
      {/* ========================================================================= */}
      {activeTab === 'explain' && (
        <div className="space-y-6">
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-6">
            <h2 className="text-lg font-semibold text-slate-100 mb-2 flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-cyan-400" />
              Interactive SHAP Explainer
            </h2>
            <p className="text-sm text-slate-400 mb-4">
              Enter any target URL to calculate exact Tree-SHAP additive feature attributions, determining exactly which lexical signals drove the AI model's verdict.
            </p>

            <div className="flex flex-col sm:flex-row gap-3 mb-4">
              <input
                type="text"
                value={explainUrl}
                onChange={e => setExplainUrl(e.target.value)}
                placeholder="https://example.com/login"
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
              <button
                onClick={() => handleComputeExplanation()}
                disabled={isExplaining}
                className="flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold px-6 py-2.5 rounded-lg text-sm transition-all disabled:opacity-50"
              >
                {isExplaining ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4 fill-current" />
                )}
                Compute Attribution
              </button>
            </div>

            {/* Quick Sample Chips */}
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span>Quick Test Targets:</span>
              <button
                onClick={() => {
                  setExplainUrl('http://192.168.1.1/login-account-update.php?token=892348');
                  handleComputeExplanation('http://192.168.1.1/login-account-update.php?token=892348');
                }}
                className="px-2.5 py-1 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded font-mono"
              >
                Raw IP Host (Phishing)
              </button>
              <button
                onClick={() => {
                  setExplainUrl('https://paypal.com.account-verify.top/signin');
                  handleComputeExplanation('https://paypal.com.account-verify.top/signin');
                }}
                className="px-2.5 py-1 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded font-mono"
              >
                Typosquat Subdomain
              </button>
              <button
                onClick={() => {
                  setExplainUrl('https://github.com/Sidd-commits/PhishNetra');
                  handleComputeExplanation('https://github.com/Sidd-commits/PhishNetra');
                }}
                className="px-2.5 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded font-mono"
              >
                Legitimate HTTPS
              </button>
            </div>
          </div>

          {/* Explanation Output Cards */}
          {explanation && (
            <div className="space-y-6">
              {/* Executive Summary Card */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-4 pb-4 border-b border-slate-800">
                  <div>
                    <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Analyzed URL</div>
                    <div className="text-sm font-mono text-cyan-300 break-all">{explanation.url}</div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div>
                      <div className="text-xs text-slate-400 font-mono">PHISHING PROBABILITY</div>
                      <div className={`text-2xl font-bold font-mono ${
                        explanation.predictedProbability >= 0.5 ? 'text-red-400' : 'text-emerald-400'
                      }`}>
                        {(explanation.predictedProbability * 100).toFixed(1)}%
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-400 font-mono">MODEL VERDICT</div>
                      <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold ${
                        explanation.predictedLabel === 1
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {explanation.predictedLabel === 1 ? <AlertTriangle className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                        {explanation.predictedLabel === 1 ? 'PHISHING THREAT' : 'BENIGN / SAFE'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800/80 mb-4">
                  <div className="text-xs text-slate-400 font-semibold mb-1 flex items-center gap-1.5">
                    <Info className="w-4 h-4 text-cyan-400" />
                    EXECUTIVE ANALYST EXPLANATION
                  </div>
                  <p className="text-sm text-slate-300 leading-relaxed">
                    {explanation.narrativeSummary}
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-red-950/20 border border-red-900/30 p-3.5 rounded-lg">
                    <div className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2">
                      Top Risk Inflators (+ Phishing Bias)
                    </div>
                    <ul className="space-y-1 text-xs text-red-300/90 font-mono">
                      {explanation.topPhishingFactors.length > 0 ? (
                        explanation.topPhishingFactors.map((f, i) => (
                          <li key={i} className="flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                            {f}
                          </li>
                        ))
                      ) : (
                        <li className="text-slate-500">None detected</li>
                      )}
                    </ul>
                  </div>

                  <div className="bg-emerald-950/20 border border-emerald-900/30 p-3.5 rounded-lg">
                    <div className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-2">
                      Top Mitigating Indicators (- Benign Bias)
                    </div>
                    <ul className="space-y-1 text-xs text-emerald-300/90 font-mono">
                      {explanation.topBenignFactors.length > 0 ? (
                        explanation.topBenignFactors.map((f, i) => (
                          <li key={i} className="flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                            {f}
                          </li>
                        ))
                      ) : (
                        <li className="text-slate-500">None detected</li>
                      )}
                    </ul>
                  </div>
                </div>
              </div>

              {/* Detailed Feature Attribution Waterfall / Bar Chart */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <BarChart2 className="w-4 h-4 text-cyan-400" />
                    Feature Attribution Breakdown (Tree-SHAP Decomposition)
                  </h3>
                  <div className="text-xs text-slate-400 font-mono">
                    Baseline expected value: <span className="text-cyan-400">{explanation.baseValue}</span>
                  </div>
                </div>

                <div className="space-y-3">
                  {explanation.attributions.map((attr, idx) => {
                    const isPhish = attr.direction === 'PHISHING';
                    return (
                      <div
                        key={idx}
                        className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-3.5 hover:border-slate-700 transition-colors"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-2">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-bold text-slate-200">
                              {attr.featureName}
                            </span>
                            <span className="text-xs text-slate-500 font-mono">
                              = {String(attr.featureValue)}
                            </span>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className={`text-xs font-mono font-bold ${
                              isPhish ? 'text-red-400' : 'text-emerald-400'
                            }`}>
                              {isPhish ? '+' : ''}{attr.shapValue.toFixed(4)} ({attr.contributionPercent.toFixed(1)}%)
                            </span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              isPhish
                                ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            }`}>
                              {attr.direction}
                            </span>
                          </div>
                        </div>

                        {/* Relative Contribution Bar */}
                        <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden mb-2">
                          <div
                            className={`h-full rounded-full ${
                              isPhish ? 'bg-gradient-to-r from-red-600 to-red-400' : 'bg-gradient-to-r from-emerald-600 to-emerald-400'
                            }`}
                            style={{ width: `${Math.min(100, Math.max(5, attr.contributionPercent))}%` }}
                          />
                        </div>

                        <div className="text-xs text-slate-400">
                          {attr.humanDescription}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: Model Registry & Continuous Retraining                            */}
      {/* ========================================================================= */}
      {activeTab === 'models' && (
        <div className="space-y-6">
          {/* Continuous Retraining Trigger Card */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
            <h2 className="text-lg font-semibold text-slate-100 mb-2 flex items-center gap-2">
              <RotateCw className="w-5 h-5 text-cyan-400" />
              Continuous Automated Retraining Pipeline
            </h2>
            <p className="text-sm text-slate-400 mb-4">
              Trigger automated training on combined datasets (baseline corpus + newly submitted honeypot threat reports). The pipeline validates F1 thresholds and can automatically promote high-performing models to live production inference.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-xs text-slate-400 font-semibold mb-1">ALGORITHM</label>
                <select
                  value={retrainAlgorithm}
                  onChange={e => setRetrainAlgorithm(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="RandomForest">RandomForestClassifier</option>
                  <option value="GradientBoosting">GradientBoostingClassifier</option>
                </select>
              </div>

              <div>
                <label className="block text-xs text-slate-400 font-semibold mb-1">AUTO-PROMOTION F1 THRESHOLD</label>
                <input
                  type="number"
                  step="0.01"
                  min="0.5"
                  max="1.0"
                  value={autoActivateThreshold}
                  onChange={e => setAutoActivateThreshold(parseFloat(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="flex items-end">
                <button
                  onClick={handleRunRetrain}
                  disabled={isRetraining}
                  className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-semibold px-4 py-2 rounded-lg text-sm transition-all disabled:opacity-50"
                >
                  {isRetraining ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <Play className="w-4 h-4 fill-current" />
                  )}
                  Launch Retraining Pipeline
                </button>
              </div>
            </div>

            {retrainResult && (
              <div className="bg-emerald-950/20 border border-emerald-500/30 p-4 rounded-lg text-sm text-emerald-300">
                <div className="font-semibold flex items-center gap-2 mb-1">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  {retrainResult.message}
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  Version: {retrainResult.newModel?.version} | F1: {retrainResult.newModel?.f1Score} | Accuracy: {retrainResult.newModel?.accuracy}
                </div>
              </div>
            )}
          </div>

          {/* Model Registry List */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <Database className="w-4 h-4 text-cyan-400" />
                Registered Model Versions ({registry?.totalModels || 0})
              </h3>
              <button
                onClick={fetchModelRegistry}
                className="p-1.5 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-slate-200 transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4">
              {registry?.registeredModels.map((model, idx) => (
                <div
                  key={idx}
                  className={`bg-slate-950/80 border rounded-xl p-5 transition-all ${
                    model.active
                      ? 'border-cyan-500/50 shadow-lg shadow-cyan-950/30'
                      : 'border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-3 mb-1">
                        <span className="font-mono text-base font-bold text-slate-100">
                          {model.version}
                        </span>
                        {model.active ? (
                          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                            ACTIVE PRODUCTION
                          </span>
                        ) : (
                          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400">
                            STANDBY ARTIFACT
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-400 flex items-center gap-4">
                        <span>Algorithm: <strong className="text-slate-300 font-mono">{model.algorithm}</strong></span>
                        <span>Trained: <strong className="text-slate-300 font-mono">{new Date(model.trainedAt).toLocaleString()}</strong></span>
                        <span>Samples: <strong className="text-slate-300 font-mono">{model.datasetSamples}</strong></span>
                      </div>
                    </div>

                    <div className="flex items-center gap-6">
                      <div className="grid grid-cols-4 gap-4 text-center">
                        <div>
                          <div className="text-[10px] text-slate-500 font-mono uppercase">ACCURACY</div>
                          <div className="text-sm font-bold text-slate-200 font-mono">{(model.accuracy * 100).toFixed(1)}%</div>
                        </div>
                        <div>
                          <div className="text-[10px] text-slate-500 font-mono uppercase">PRECISION</div>
                          <div className="text-sm font-bold text-slate-200 font-mono">{(model.precision * 100).toFixed(1)}%</div>
                        </div>
                        <div>
                          <div className="text-[10px] text-slate-500 font-mono uppercase">RECALL</div>
                          <div className="text-sm font-bold text-slate-200 font-mono">{(model.recall * 100).toFixed(1)}%</div>
                        </div>
                        <div>
                          <div className="text-[10px] text-slate-500 font-mono uppercase">F1-SCORE</div>
                          <div className="text-sm font-bold text-cyan-400 font-mono">{(model.f1Score * 100).toFixed(1)}%</div>
                        </div>
                      </div>

                      {!model.active && (
                        <button
                          onClick={() => handleActivateModel(model.version)}
                          disabled={activatingVersion === model.version}
                          className="px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          {activatingVersion === model.version ? 'Hot-Swapping...' : 'Activate Model'}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: Data Drift & Population Stability Index (PSI)                     */}
      {/* ========================================================================= */}
      {activeTab === 'drift' && (
        <div className="space-y-6">
          {driftReport && (
            <>
              {/* Drift Status Banner */}
              <div className={`border rounded-xl p-6 backdrop-blur-md ${
                driftReport.overallDriftStatus === 'STABLE'
                  ? 'bg-emerald-950/20 border-emerald-500/30'
                  : driftReport.overallDriftStatus === 'MODERATE'
                  ? 'bg-amber-950/20 border-amber-500/30'
                  : 'bg-red-950/20 border-red-500/30'
              }`}>
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <span className={`p-2.5 rounded-lg ${
                      driftReport.overallDriftStatus === 'STABLE'
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : driftReport.overallDriftStatus === 'MODERATE'
                        ? 'bg-amber-500/20 text-amber-400'
                        : 'bg-red-500/20 text-red-400'
                    }`}>
                      <Activity className="w-6 h-6" />
                    </span>
                    <div>
                      <div className="text-xs font-mono uppercase tracking-wider text-slate-400">
                        OVERALL DATA DRIFT STATUS
                      </div>
                      <div className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
                        {driftReport.overallDriftStatus}
                        <span className="text-xs text-slate-400 font-normal font-sans">
                          (Baseline: {driftReport.baselineSamples} samples vs Live: {driftReport.liveSamples} samples)
                        </span>
                      </div>
                    </div>
                  </div>

                  <button
                    onClick={fetchDriftMetrics}
                    disabled={loadingDrift}
                    className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-slate-200 px-4 py-2 rounded-lg border border-slate-700 text-xs font-medium"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${loadingDrift ? 'animate-spin' : ''}`} />
                    Refresh Metrics
                  </button>
                </div>

                <div className="mt-4 pt-4 border-t border-slate-800/80 text-sm text-slate-300">
                  <strong className="text-slate-100">Automated Recommendation:</strong> {driftReport.recommendation}
                </div>
              </div>

              {/* PSI Feature Grid */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <TrendingUp className="w-4 h-4 text-cyan-400" />
                    Per-Feature Population Stability Index (PSI) & KS Statistics
                  </h3>
                  <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
                    <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400" /> Stable (&lt; 0.10)</span>
                    <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-400" /> Moderate (0.10 - 0.25)</span>
                    <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-400" /> Drifted (&ge; 0.25)</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
                  {driftReport.features.map((feat, idx) => {
                    const isDrifted = feat.status === 'DRIFTED';
                    const isMod = feat.status === 'MODERATE';
                    return (
                      <div
                        key={idx}
                        className={`bg-slate-950 p-3.5 rounded-lg border transition-all ${
                          isDrifted
                            ? 'border-red-500/50 bg-red-950/10'
                            : isMod
                            ? 'border-amber-500/40 bg-amber-950/10'
                            : 'border-slate-800/80'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="text-xs font-mono font-bold text-slate-200">
                            {feat.featureName}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            isDrifted
                              ? 'bg-red-500/20 text-red-400'
                              : isMod
                              ? 'bg-amber-500/20 text-amber-400'
                              : 'bg-emerald-500/20 text-emerald-400'
                          }`}>
                            {feat.status}
                          </span>
                        </div>

                        <div className="flex items-center justify-between text-xs text-slate-400 font-mono mb-2">
                          <span>PSI Score: <strong className="text-slate-200">{feat.psiScore.toFixed(4)}</strong></span>
                          <span>KS Stat: <strong className="text-slate-200">{feat.ksStatistic.toFixed(3)}</strong> (p={feat.pValue.toFixed(2)})</span>
                        </div>

                        {/* Visual Meter Bar */}
                        <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              isDrifted ? 'bg-red-400' : isMod ? 'bg-amber-400' : 'bg-emerald-400'
                            }`}
                            style={{ width: `${Math.min(100, Math.max(8, feat.psiScore * 250))}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: Adversarial Robustness & Evasion Hardening Lab                     */}
      {/* ========================================================================= */}
      {activeTab === 'adversarial' && (
        <div className="space-y-6">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
            <h2 className="text-lg font-semibold text-slate-100 mb-2 flex items-center gap-2">
              <Crosshair className="w-5 h-5 text-cyan-400" />
              Adversarial Evasion Simulator
            </h2>
            <p className="text-sm text-slate-400 mb-4">
              Test model resilience against 6 sophisticated evasion tactics: Unicode Homoglyphs, Subdomain Packing, Benign Keyword Stuffing, Length Inflation, TLD Masquerading, and %-Encoding Obfuscation.
            </p>

            <div className="flex flex-col sm:flex-row gap-3 mb-4">
              <input
                type="text"
                value={adversarialTestUrl}
                onChange={e => setAdversarialTestUrl(e.target.value)}
                placeholder="http://192.168.1.100/admin-login.php"
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
              <button
                onClick={handleRunAdversarial}
                disabled={loadingAdversarial}
                className="flex items-center justify-center gap-2 bg-gradient-to-r from-red-500 to-rose-600 hover:from-red-400 hover:to-rose-500 text-slate-950 font-semibold px-6 py-2.5 rounded-lg text-sm transition-all disabled:opacity-50"
              >
                {loadingAdversarial ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Crosshair className="w-4 h-4" />
                )}
                Run Evasion Test Suite
              </button>
            </div>
          </div>

          {adversarialReport && (
            <div className="space-y-6">
              {/* Robustness Scorecard */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
                  <div className="text-xs text-slate-400 font-mono uppercase">Overall Robustness Score</div>
                  <div className="text-3xl font-bold text-cyan-400 font-mono mt-1">
                    {adversarialReport.overallRobustnessScore.toFixed(1)}%
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
                  <div className="text-xs text-slate-400 font-mono uppercase">Evasion Rate</div>
                  <div className={`text-3xl font-bold font-mono mt-1 ${
                    adversarialReport.evasionRate > 0.3 ? 'text-red-400' : 'text-emerald-400'
                  }`}>
                    {(adversarialReport.evasionRate * 100).toFixed(1)}%
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-xl">
                  <div className="text-xs text-slate-400 font-mono uppercase">Hardening Status</div>
                  <div className="text-xl font-bold text-slate-100 font-mono mt-2">
                    <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                      adversarialReport.hardeningStatus === 'ROBUST'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}>
                      {adversarialReport.hardeningStatus}
                    </span>
                  </div>
                </div>
              </div>

              {/* Perturbation Results Table */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
                <h3 className="text-base font-semibold text-slate-100 mb-4">
                  Perturbation Tactics & Detection Resilience
                </h3>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase">
                        <th className="pb-3 font-semibold">Attack Vector</th>
                        <th className="pb-3 font-semibold">Perturbed Adversarial URL</th>
                        <th className="pb-3 font-semibold text-center">Original Score</th>
                        <th className="pb-3 font-semibold text-center">Perturbed Score</th>
                        <th className="pb-3 font-semibold text-center">Delta (&Delta;)</th>
                        <th className="pb-3 font-semibold text-right">Evasion Outcome</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {adversarialReport.results.map((res, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30">
                          <td className="py-3 font-bold text-cyan-400">
                            {res.attackType}
                          </td>
                          <td className="py-3 text-slate-300 max-w-xs truncate" title={res.perturbedUrl}>
                            {res.perturbedUrl}
                          </td>
                          <td className="py-3 text-center text-slate-300">
                            {res.originalScore.toFixed(1)}%
                          </td>
                          <td className="py-3 text-center text-slate-300">
                            {res.perturbedScore.toFixed(1)}%
                          </td>
                          <td className={`py-3 text-center font-bold ${
                            res.scoreDiff > 20 ? 'text-red-400' : 'text-emerald-400'
                          }`}>
                            {res.scoreDiff > 0 ? '-' : '+'}{Math.abs(res.scoreDiff).toFixed(1)}%
                          </td>
                          <td className="py-3 text-right">
                            {res.evaded ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                                EVADED
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                                BLOCKED
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
