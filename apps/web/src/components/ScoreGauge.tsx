import React from 'react';
import { ThreatVerdict, RiskLevel } from '@phishnetra/shared';
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

interface ScoreGaugeProps {
  score: number;
  verdict: ThreatVerdict;
  riskLevel: RiskLevel;
  confidence: number;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score,
  verdict,
  riskLevel,
  confidence
}) => {
  // Determine color accents based on verdict & risk level
  const getColorScheme = () => {
    switch (verdict) {
      case 'SAFE':
        return {
          stroke: '#00e676',
          bgGlow: 'shadow-emerald-500/10 border-emerald-500/30',
          textColor: 'text-emerald-400',
          badgeBg: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
          icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />
        };
      case 'SUSPICIOUS':
        return {
          stroke: '#ffb300',
          bgGlow: 'shadow-amber-500/10 border-amber-500/30',
          textColor: 'text-amber-400',
          badgeBg: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
          icon: <AlertTriangle className="w-5 h-5 text-amber-400" />
        };
      case 'PHISHING':
      default:
        return {
          stroke: '#ff3366',
          bgGlow: 'shadow-rose-500/20 border-rose-500/30',
          textColor: 'text-rose-400',
          badgeBg: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          icon: <ShieldAlert className="w-5 h-5 text-rose-400" />
        };
    }
  };

  const colors = getColorScheme();
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.min(100, Math.max(0, score));
  const strokeDashoffset = circumference - (progress / 100) * circumference;

  return (
    <div className={`p-6 rounded-2xl glass-panel ${colors.bgGlow} transition-all flex flex-col items-center justify-center text-center relative overflow-hidden`}>
      {/* Background Accent Glow */}
      <div
        className="absolute w-40 h-40 rounded-full blur-3xl opacity-20 pointer-events-none"
        style={{ backgroundColor: colors.stroke }}
      />

      {/* Circular Gauge */}
      <div className="relative w-44 h-44 flex items-center justify-center mb-4">
        <svg className="w-full h-full transform -rotate-90">
          {/* Track */}
          <circle
            cx="88"
            cy="88"
            r={radius}
            className="text-slate-800"
            strokeWidth="10"
            stroke="currentColor"
            fill="transparent"
          />
          {/* Progress fill */}
          <circle
            cx="88"
            cy="88"
            r={radius}
            stroke={colors.stroke}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Score Readout Center */}
        <div className="absolute flex flex-col items-center justify-center">
          <span className="text-3xl font-extrabold font-mono tracking-tight text-white">
            {score.toFixed(1)}
          </span>
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Risk Score
          </span>
        </div>
      </div>

      {/* Verdict & Risk Level Badges */}
      <div className="flex items-center space-x-2 mb-3">
        <div className={`flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-bold border ${colors.badgeBg}`}>
          {colors.icon}
          <span>{verdict}</span>
        </div>
        <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-mono">
          {riskLevel} RISK
        </span>
      </div>

      {/* Model Confidence Metric */}
      <div className="w-full max-w-xs mt-2 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
        <span>Classifier Confidence:</span>
        <span className="font-mono font-bold text-slate-200">
          {(confidence * 100).toFixed(0)}%
        </span>
      </div>
    </div>
  );
};
