import React, { useState } from 'react';
import { EvidenceItem, DetectionLayer } from '@phishnetra/shared';
import {
  AlertCircle,
  AlertTriangle,
  Info,
  CheckCircle2,
  ShieldCheck,
  Filter
} from 'lucide-react';

interface EvidenceTableProps {
  evidence: EvidenceItem[];
}

export const EvidenceTable: React.FC<EvidenceTableProps> = ({ evidence }) => {
  const [selectedLayer, setSelectedLayer] = useState<string>('ALL');

  const layers: { id: string; label: string }[] = [
    { id: 'ALL', label: 'All Signals' },
    { id: 'URL', label: 'URL Intel' },
    { id: 'DOMAIN', label: 'Domain & RDAP' },
    { id: 'DNS', label: 'DNS & IP' },
    { id: 'TLS', label: 'TLS / SSL' },
    { id: 'REPUTATION', label: 'Reputation' },
    { id: 'CONTENT', label: 'Page Content' },
    { id: 'FORM', label: 'Forms & Auth' },
    { id: 'BRAND', label: 'Brand Intel' },
    { id: 'NETWORK', label: 'Network' },
    { id: 'ML', label: 'ML Model' }
  ];

  const filteredEvidence = selectedLayer === 'ALL'
    ? evidence
    : evidence.filter(item => (item.layer || 'URL') === selectedLayer);

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
            <AlertCircle className="w-3 h-3 text-rose-400" />
            <span>CRITICAL</span>
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <AlertCircle className="w-3 h-3 text-rose-400" />
            <span>HIGH</span>
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            <span>MEDIUM</span>
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-sky-500/15 text-sky-300 border border-sky-500/30">
            <Info className="w-3 h-3 text-sky-400" />
            <span>LOW</span>
          </span>
        );
      case 'INFO':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            <span>INFO</span>
          </span>
        );
    }
  };

  const getLayerBadge = (layer?: DetectionLayer | string) => {
    const l = layer || 'URL';
    const colors: Record<string, string> = {
      URL: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
      DOMAIN: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
      DNS: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
      TLS: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      REPUTATION: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      CONTENT: 'bg-teal-500/10 text-teal-300 border-teal-500/30',
      FORM: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
      BRAND: 'bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/30',
      NETWORK: 'bg-sky-500/10 text-sky-300 border-sky-500/30',
      ML: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30'
    };
    return (
      <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${colors[l] || colors.URL}`}>
        {l}
      </span>
    );
  };

  if (!evidence || evidence.length === 0) {
    return (
      <div className="p-8 text-center text-slate-400 rounded-xl bg-slate-900/40 border border-slate-800">
        <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
        <p className="text-sm">No anomalous risk indicators triggered for this URL.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Layer Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2 p-1.5 bg-slate-950/60 rounded-xl border border-slate-800/80">
        <div className="flex items-center space-x-1.5 px-3 py-1 text-slate-400 text-xs font-medium">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span>Layer Filter:</span>
        </div>
        {layers.map(tab => {
          const count = tab.id === 'ALL'
            ? evidence.length
            : evidence.filter(item => (item.layer || 'URL') === tab.id).length;
          
          const isActive = selectedLayer === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setSelectedLayer(tab.id)}
              className={`px-3 py-1 text-xs rounded-lg font-medium transition-all flex items-center space-x-1.5 ${
                isActive
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <span>{tab.label}</span>
              <span className={`px-1.5 py-0.2 rounded-full text-[10px] ${isActive ? 'bg-slate-950/20 text-slate-950' : 'bg-slate-800 text-slate-400'}`}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800/80 bg-slate-900/60 shadow-lg">
        <table className="w-full text-left text-xs sm:text-sm">
          <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
            <tr>
              <th className="py-3 px-4">Layer</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Indicator / Rule</th>
              <th className="py-3 px-4">Observed Value</th>
              <th className="py-3 px-4">Analyst Explanation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filteredEvidence.map((item, idx) => (
              <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                <td className="py-3 px-4 whitespace-nowrap">
                  {getLayerBadge(item.layer)}
                </td>
                <td className="py-3 px-4 whitespace-nowrap">
                  {getSeverityBadge(item.severity)}
                </td>
                <td className="py-3 px-4 font-mono font-medium text-slate-200">
                  {item.featureKey}
                </td>
                <td className="py-3 px-4 font-mono text-cyan-300 font-semibold max-w-[180px] truncate" title={String(item.featureValue)}>
                  {String(item.featureValue)}
                </td>
                <td className="py-3 px-4 text-slate-300 leading-relaxed max-w-md">
                  {item.description}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
