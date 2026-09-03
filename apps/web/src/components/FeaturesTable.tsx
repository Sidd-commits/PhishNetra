import React from 'react';
import { URLFeatureVector } from '@phishnetra/shared';
import { Cpu } from 'lucide-react';

interface FeaturesTableProps {
  features?: URLFeatureVector;
}

export const FeaturesTable: React.FC<FeaturesTableProps> = ({ features }) => {
  if (!features) {
    return null;
  }

  const featureEntries = Object.entries(features);

  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 shadow-lg">
      <div className="flex items-center space-x-2 mb-4 pb-3 border-b border-slate-800">
        <Cpu className="w-4 h-4 text-cyan-400" />
        <h3 className="text-sm font-bold text-slate-200 tracking-wide uppercase font-mono">
          Deterministic URL Feature Vector ({featureEntries.length} Signals)
        </h3>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        {featureEntries.map(([key, val]) => (
          <div
            key={key}
            className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/60 flex flex-col justify-between"
          >
            <span className="text-[11px] font-mono text-slate-400 truncate mb-1" title={key}>
              {key}
            </span>
            <span className="text-sm font-mono font-bold text-cyan-300">
              {typeof val === 'number' && !Number.isInteger(val) ? val.toFixed(3) : String(val)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
