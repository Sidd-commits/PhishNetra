import React from 'react';
import { ShieldAlert, Lock, Info } from 'lucide-react';

interface ZeroTrustBannerProps {
  hasTls?: boolean;
  verdict: string;
}

export const ZeroTrustBanner: React.FC<ZeroTrustBannerProps> = ({ hasTls, verdict }) => {
  return (
    <div className="relative overflow-hidden rounded-xl bg-gradient-to-r from-slate-900/90 via-slate-900/60 to-slate-950 border border-cyan-500/20 p-4 shadow-xl">
      <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 rounded-full blur-2xl pointer-events-none" />
      <div className="flex items-start space-x-3.5">
        <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-bold tracking-wider uppercase text-cyan-400">
              Zero-Trust Security Principle
            </span>
            {hasTls && (
              <span className="inline-flex items-center space-x-1 px-2 py-0.2 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Lock className="w-2.5 h-2.5" />
                <span>HTTPS ENCRYPTED</span>
              </span>
            )}
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            <strong className="text-cyan-300">PhishNetra does not trust a webpage based on a single signal.</strong> A valid HTTPS certificate, familiar branding, or clean reputation alone does not guarantee that a destination is safe. Final verdict ({verdict}) is synthesized across all independent intelligence layers including DOM structure, form destinations, brand consistency, and behavioral signals.
          </p>
        </div>
      </div>
    </div>
  );
};
