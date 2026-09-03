import React from 'react';
import { MultiLayerData, LayerStatus } from '@phishnetra/shared';
import {
  Link2,
  Globe2,
  Network,
  Lock,
  Radio,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  Calendar,
  Server,
  ShieldCheck,
  ShieldAlert
} from 'lucide-react';

interface LayersBreakdownProps {
  layers?: MultiLayerData;
  layerStatuses?: Record<string, LayerStatus>;
}

export const LayersBreakdown: React.FC<LayersBreakdownProps> = ({ layers, layerStatuses }) => {
  if (!layers) return null;

  const renderStatusPill = (status?: LayerStatus) => {
    switch (status) {
      case 'SUCCESS':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" />
            <span>ACTIVE</span>
          </span>
        );
      case 'PARTIAL':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" />
            <span>PARTIAL</span>
          </span>
        );
      case 'NOT_CONFIGURED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-500/15 text-slate-400 border border-slate-500/30">
            <HelpCircle className="w-3 h-3" />
            <span>NOT CONFIGURED</span>
          </span>
        );
      case 'FAILED':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3 h-3" />
            <span>FAILED</span>
          </span>
        );
    }
  };

  const getAgeBadge = (cat?: string, days?: number | null) => {
    if (days === null || days === undefined) {
      return <span className="text-slate-500 font-mono text-xs">Unknown Age</span>;
    }
    if (days < 30) {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-xs font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40">
          <Calendar className="w-3 h-3" />
          <span>{days} Days (&lt; 30d HIGH RISK)</span>
        </span>
      );
    }
    if (days < 90) {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
          <Calendar className="w-3 h-3" />
          <span>{days} Days (30-90d Young)</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
        <Calendar className="w-3 h-3" />
        <span>{Math.floor(days / 365)}y {days % 365}d Established</span>
      </span>
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-mono uppercase tracking-wider text-slate-400 font-semibold">
          Multi-Layer Threat Intelligence Breakdown (5+ Layers)
        </h3>
        <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2.5 py-0.5 rounded-full border border-cyan-500/20">
          Zero-Trust Orchestrator
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Layer 1: URL Intelligence */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-cyan-500/40 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2 text-cyan-400">
                <Link2 className="w-4 h-4" />
                <span className="font-mono text-xs font-bold uppercase tracking-wider">Layer 1: URL Intel</span>
              </div>
              {renderStatusPill(layers.url?.status || layerStatuses?.URL)}
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Shortener:</span>
                <span className="font-mono text-slate-200">
                  {layers.url?.isShortener ? `YES (${layers.url.shortenerProvider})` : 'NO'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Punycode / IDN:</span>
                <span className="font-mono text-slate-200">
                  {layers.url?.isPunycode ? `YES (${layers.url.unicodeHostname})` : 'NO'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Shannon Entropy:</span>
                <span className="font-mono text-cyan-300 font-semibold">{layers.url?.entropy}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Custom Port:</span>
                <span className="font-mono text-slate-200">{layers.url?.customPort ? layers.url.customPort : 'Default'}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Obfuscated Hex:</span>
                <span className="font-mono text-slate-200">
                  {layers.url?.obfuscatedEncodings?.length ? layers.url.obfuscatedEncodings.join(', ') : 'None'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Layer 2: Domain Intelligence & RDAP */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-purple-500/40 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2 text-purple-400">
                <Globe2 className="w-4 h-4" />
                <span className="font-mono text-xs font-bold uppercase tracking-wider">Layer 2: Domain & RDAP</span>
              </div>
              {renderStatusPill(layers.domain?.status || layerStatuses?.DOMAIN)}
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Registrable Domain:</span>
                <span className="font-mono text-purple-300 font-semibold">{layers.domain?.registrableDomain}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Domain Age:</span>
                <div>{getAgeBadge(layers.domain?.domainAgeCategory, layers.domain?.domainAgeDays)}</div>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Registrar:</span>
                <span className="font-mono text-slate-200 truncate max-w-[140px]" title={layers.domain?.registrar || 'N/A'}>
                  {layers.domain?.registrar || 'Unavailable'}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Privacy Proxy:</span>
                <span className="font-mono text-slate-200">
                  {layers.domain?.isPrivacyProtected ? 'Enabled' : 'Public / Direct'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Layer 3: DNS & IP Intelligence */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-blue-500/40 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2 text-blue-400">
                <Network className="w-4 h-4" />
                <span className="font-mono text-xs font-bold uppercase tracking-wider">Layer 3: DNS & IP</span>
              </div>
              {renderStatusPill(layers.dns?.status || layerStatuses?.DNS)}
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Resolved IPs:</span>
                <span className="font-mono text-blue-300 font-semibold">
                  {layers.dns?.resolvedIps?.length || 0} IPs
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">IPv4 / IPv6:</span>
                <span className="font-mono text-slate-200">
                  {layers.dns?.ipv4Count || 0} v4 / {layers.dns?.ipv6Count || 0} v6
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">MX Mail Records:</span>
                <span className="font-mono text-slate-200">
                  {layers.dns?.hasMx ? 'Configured' : 'None Detected'}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Primary ASN / Org:</span>
                <span className="font-mono text-slate-200 truncate max-w-[140px]" title={layers.dns?.ipDetails?.[0]?.org || 'N/A'}>
                  {layers.dns?.ipDetails?.[0]?.org || 'Public System'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Layer 4: TLS / SSL Intelligence */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-emerald-500/40 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2 text-emerald-400">
                <Lock className="w-4 h-4" />
                <span className="font-mono text-xs font-bold uppercase tracking-wider">Layer 4: TLS / SSL</span>
              </div>
              {renderStatusPill(layers.tls?.status || layerStatuses?.TLS)}
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Transport Security:</span>
                <span className={`font-mono font-bold ${layers.tls?.hasTls ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {layers.tls?.hasTls ? 'HTTPS (TLS)' : 'Plain HTTP'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Certificate Status:</span>
                <span className="font-mono text-slate-200">
                  {layers.tls?.certificateExpired
                    ? 'EXPIRED'
                    : layers.tls?.certificateValid
                    ? 'VALID ROOT CA'
                    : 'UNVERIFIED / NONE'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Issuer:</span>
                <span className="font-mono text-slate-200 truncate max-w-[140px]" title={layers.tls?.issuer || 'N/A'}>
                  {layers.tls?.issuer || 'None'}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Days Until Expiry:</span>
                <span className="font-mono text-slate-200">
                  {layers.tls?.daysUntilExpiry !== null && layers.tls?.daysUntilExpiry !== undefined
                    ? `${layers.tls.daysUntilExpiry} days`
                    : 'N/A'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Layer 5: Reputation Intelligence */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-amber-500/40 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2 text-amber-400">
                <Radio className="w-4 h-4" />
                <span className="font-mono text-xs font-bold uppercase tracking-wider">Layer 5: Threat Feeds</span>
              </div>
              {renderStatusPill(layers.reputation?.status || layerStatuses?.REPUTATION)}
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Blacklist Status:</span>
                <span className={`font-mono font-bold ${layers.reputation?.isListedMalicious ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {layers.reputation?.isListedMalicious ? 'LISTED THREAT' : 'CLEAN RECORD'}
                </span>
              </div>
              {layers.reputation?.providers?.map((p, idx) => (
                <div key={idx} className="flex justify-between py-1 border-b border-slate-800/50 last:border-0">
                  <span className="text-slate-400">{p.providerName}:</span>
                  <span className="font-mono text-[11px] text-slate-300">
                    {p.isConfigured ? (p.malicious ? 'MALICIOUS' : 'CLEAN') : 'Not Configured'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Layer 6: ML Model Inference */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-indigo-500/40 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2 text-indigo-400">
                <Cpu className="w-4 h-4" />
                <span className="font-mono text-xs font-bold uppercase tracking-wider">Layer 6: AI / ML Model</span>
              </div>
              {renderStatusPill(layers.ml?.status || layerStatuses?.ML)}
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Phishing Probability:</span>
                <span className="font-mono text-indigo-300 font-bold">
                  {(layers.ml?.phishingProbability * 100).toFixed(1)}%
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Model Confidence:</span>
                <span className="font-mono text-slate-200">
                  {(layers.ml?.confidence * 100).toFixed(1)}%
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Model Version:</span>
                <span className="font-mono text-slate-200">{layers.ml?.modelVersion}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Inference Latency:</span>
                <span className="font-mono text-slate-200">{layers.ml?.inferenceTimeMs} ms</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
