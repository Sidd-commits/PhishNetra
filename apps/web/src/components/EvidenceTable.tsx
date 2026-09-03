import React from 'react';
import { EvidenceItem } from '@phishnetra/shared';
import {
  AlertCircle,
  AlertTriangle,
  Info,
  CheckCircle2,
  ShieldCheck
} from 'lucide-react';

interface EvidenceTableProps {
  evidence: EvidenceItem[];
}

export const EvidenceTable: React.FC<EvidenceTableProps> = ({ evidence }) => {
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

  if (!evidence || evidence.length === 0) {
    return (
      <div className="p-8 text-center text-slate-400 rounded-xl bg-slate-900/40 border border-slate-800">
        <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
        <p className="text-sm">No anomalous risk indicators triggered for this URL.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800/80 bg-slate-900/60 shadow-lg">
      <table className="w-full text-left text-xs sm:text-sm">
        <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
          <tr>
            <th className="py-3 px-4">Severity</th>
            <th className="py-3 px-4">Indicator / Rule</th>
            <th className="py-3 px-4">Observed Value</th>
            <th className="py-3 px-4">Analyst Explanation</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {evidence.map((item, idx) => (
            <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
              <td className="py-3 px-4 whitespace-nowrap">
                {getSeverityBadge(item.severity)}
              </td>
              <td className="py-3 px-4 font-mono font-medium text-slate-200">
                {item.featureKey}
              </td>
              <td className="py-3 px-4 font-mono text-cyan-300 font-semibold">
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
  );
};
