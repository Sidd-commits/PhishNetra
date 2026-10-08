import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { D3FENDMatrixCoverage } from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  ShieldCheck,
  Layers,
  Award,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  Download,
  Terminal,
  ExternalLink,
  Shield,
  Zap,
  Check
} from 'lucide-react';

export const D3FENDMatrixPage: React.FC = () => {
  const { showToast } = useToast();
  const [coverage, setCoverage] = useState<D3FENDMatrixCoverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTactic, setSelectedTactic] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadMatrix();
  }, []);

  const loadMatrix = async () => {
    setLoading(true);
    try {
      const data = await api.getD3FENDMatrix();
      setCoverage(data);
    } catch (err: any) {
      showToast('error', 'Failed to load D3FEND Matrix', err.message);
    } finally {
      setLoading(false);
    }
  };

  const filteredTechniques = coverage?.techniques.filter(tech => {
    const matchesTactic = selectedTactic === 'ALL' || tech.tactic === selectedTactic;
    const matchesSearch =
      tech.techniqueName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tech.d3fendId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tech.phishNetraCapability.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesTactic && matchesSearch;
  }) || [];

  const exportReport = () => {
    if (!coverage) return;
    const blob = new Blob([JSON.stringify(coverage, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishnetra-mitre-d3fend-matrix-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('success', 'Export Complete', 'MITRE D3FEND matrix exported as JSON');
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-purple-950/70 via-slate-900 to-slate-900 border border-purple-500/20 p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
                <Shield className="w-5 h-5" />
              </div>
              <h1 className="text-xl font-bold text-white tracking-wide">
                MITRE D3FEND Defensive Countermeasure Matrix
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded-full font-semibold">
                Milestone 18
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-400 max-w-2xl leading-relaxed">
              Maps PhishNetra's multi-layered cybersecurity architecture directly against the NSA-funded MITRE D3FEND cyber defense matrix across Model, Harden, Detect, Isolate, and Deceive tactical pillars.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={exportReport}
              className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center space-x-1.5"
            >
              <Download className="w-3.5 h-3.5 text-purple-400" />
              <span>Export Matrix JSON</span>
            </button>
            <button
              onClick={loadMatrix}
              className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Refresh Matrix"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* KPI Cards: 5 Tactics */}
      {coverage && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <div className="p-4 rounded-xl bg-slate-900/90 border border-purple-500/30 shadow-lg space-y-1">
            <span className="text-[10px] font-mono uppercase text-slate-500 block">Overall Posture</span>
            <div className="text-2xl font-bold font-mono text-purple-400">
              {coverage.overallDefensivePostureScore}%
            </div>
            <span className="text-[10px] text-slate-400">{coverage.verifiedTechniques}/{coverage.totalTechniques} Verified</span>
          </div>

          {Object.entries(coverage.tacticCoverage).map(([tactic, score]) => (
            <div key={tactic} className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-lg space-y-1">
              <span className="text-[10px] font-mono uppercase text-slate-500 block">{tactic}</span>
              <div className="text-xl font-bold font-mono text-white">
                {score}%
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1">
                <div
                  className="h-full bg-purple-500 rounded-full"
                  style={{ width: `${score}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/90 border border-slate-800 p-3 rounded-2xl">
        <div className="flex items-center space-x-1 overflow-x-auto w-full sm:w-auto">
          {['ALL', 'MODEL', 'HARDEN', 'DETECT', 'ISOLATE', 'DECEIVE'].map((tactic) => (
            <button
              key={tactic}
              onClick={() => setSelectedTactic(tactic)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                selectedTactic === tactic
                  ? 'bg-purple-500 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              {tactic}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search technique or capability..."
            className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-purple-500"
          />
        </div>
      </div>

      {/* Techniques Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase">
                <th className="py-3 px-4">D3FEND ID</th>
                <th className="py-3 px-4">Technique</th>
                <th className="py-3 px-4">Tactic</th>
                <th className="py-3 px-4">PhishNetra Implementation Capability</th>
                <th className="py-3 px-4 text-center">Score</th>
                <th className="py-3 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredTechniques.map((tech) => (
                <tr key={tech.d3fendId} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3.5 px-4 font-mono font-bold text-purple-300">
                    {tech.d3fendId}
                  </td>
                  <td className="py-3.5 px-4 font-semibold text-white">
                    {tech.techniqueName}
                  </td>
                  <td className="py-3.5 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                      {tech.tactic}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-slate-300 text-xs">
                    {tech.phishNetraCapability}
                  </td>
                  <td className="py-3.5 px-4 text-center font-mono font-bold text-emerald-400">
                    {tech.coverageScore}%
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 inline-flex items-center space-x-1">
                      <CheckCircle2 className="w-2.5 h-2.5" />
                      <span>{tech.verificationStatus}</span>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
