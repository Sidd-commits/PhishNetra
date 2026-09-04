import React from 'react';
import { PageAnalysisResult } from '@phishnetra/shared';
import {
  ShieldAlert,
  ShieldCheck,
  Globe,
  ArrowRight,
  FormInput,
  KeyRound,
  FileCode2,
  AlertTriangle,
  Layers,
  Network,
  EyeOff,
  ExternalLink,
  Flame,
  CheckCircle2,
  XCircle,
  Clock,
  Ban
} from 'lucide-react';

interface PageAnalysisViewProps {
  pageAnalysis?: PageAnalysisResult;
}

export const PageAnalysisView: React.FC<PageAnalysisViewProps> = ({ pageAnalysis }) => {
  if (!pageAnalysis) return null;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>ACQUISITION COMPLETE</span>
          </span>
        );
      case 'BLOCKED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40 animate-pulse">
            <Ban className="w-3.5 h-3.5" />
            <span>SSRF / SECURITY BLOCKED</span>
          </span>
        );
      case 'TIMEOUT':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
            <Clock className="w-3.5 h-3.5" />
            <span>TIMEOUT</span>
          </span>
        );
      case 'SKIPPED':
      case 'NOT_REQUESTED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-slate-500/15 text-slate-400 border border-slate-500/30">
            <span>NOT INSPECTED</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3.5 h-3.5" />
            <span>FAILED</span>
          </span>
        );
    }
  };

  const hasBrandMismatch = pageAnalysis.brandFindings?.some(b => b.isMismatch);
  const mismatchBrand = pageAnalysis.brandFindings?.find(b => b.isMismatch);

  return (
    <div className="space-y-6">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <Layers className="w-5 h-5 text-indigo-400" />
            <h3 className="text-base font-semibold text-slate-200">Web Content &amp; DOM Intelligence</h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Passive browser isolation, DOM structure extraction, form credential destination analysis, and brand verification
          </p>
        </div>
        <div className="flex items-center space-x-3">
          {getStatusBadge(pageAnalysis.status)}
          {pageAnalysis.acquisitionTimeMs > 0 && (
            <span className="text-xs font-mono text-slate-500">
              {pageAnalysis.acquisitionTimeMs}ms
            </span>
          )}
        </div>
      </div>

      {/* SSRF Block Alert Banner */}
      {pageAnalysis.status === 'BLOCKED' && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 flex items-start space-x-3">
          <Ban className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="text-sm font-semibold text-rose-300">SSRF &amp; Private Network Defense Triggered</h4>
            <p className="text-xs text-rose-200/80 leading-relaxed">
              {pageAnalysis.blockReason || 'The requested URL or an intermediate redirect resolved to a prohibited loopback, RFC1918 private, link-local, or cloud metadata address. Content acquisition was safely terminated.'}
            </p>
          </div>
        </div>
      )}

      {/* Brand Impersonation Alert Banner */}
      {hasBrandMismatch && mismatchBrand && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/50 flex items-start space-x-3">
          <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono uppercase tracking-wider font-bold bg-rose-500/30 text-rose-300 px-2 py-0.5 rounded">
                CRITICAL BRAND MISMATCH
              </span>
              <h4 className="text-sm font-semibold text-rose-200">
                Impersonation of {mismatchBrand.claimedBrand} Detected
              </h4>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              The webpage claims association with <strong className="text-white font-mono">{mismatchBrand.claimedBrand}</strong>, but is hosted on an unrelated domain (<strong className="text-rose-300 font-mono">{mismatchBrand.actualDomain}</strong>). Authentic domain is <strong className="text-emerald-400 font-mono">{mismatchBrand.authenticDomain}</strong>.
            </p>
          </div>
        </div>
      )}

      {/* Verified Brand Banner */}
      {!hasBrandMismatch && pageAnalysis.brandFindings && pageAnalysis.brandFindings.length > 0 && (
        <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/30 flex items-center space-x-3">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          <p className="text-xs text-emerald-300">
            Verified authentic brand alignment: Page references <strong>{pageAnalysis.brandFindings[0].claimedBrand}</strong> on its official domain (<strong>{pageAnalysis.brandFindings[0].actualDomain}</strong>).
          </p>
        </div>
      )}

      {/* Content Signals Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Forms / Inputs</span>
            <FormInput className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-slate-200">
              {pageAnalysis.domMetrics?.formsCount ?? pageAnalysis.forms.length}
              <span className="text-xs font-normal text-slate-400 font-sans ml-1">
                ({pageAnalysis.domMetrics?.inputsCount ?? 0} inputs)
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {pageAnalysis.domMetrics?.passwordInputsCount ? (
                <span className="text-amber-400 font-medium">
                  {pageAnalysis.domMetrics.passwordInputsCount} password field(s)
                </span>
              ) : (
                'No password inputs'
              )}
            </p>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Redirect Hops</span>
            <Globe className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-slate-200">
              {pageAnalysis.redirectCount}
              <span className="text-xs font-normal text-slate-400 font-sans ml-1">
                {pageAnalysis.redirectCount === 1 ? 'hop' : 'hops'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {pageAnalysis.redirectCount >= 2 ? (
                <span className="text-amber-400 font-medium">Chain monitored</span>
              ) : (
                'Direct navigation'
              )}
            </p>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Scripts &amp; Iframes</span>
            <FileCode2 className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-slate-200">
              {pageAnalysis.domMetrics?.scriptsCount ?? pageAnalysis.scripts.length}
              <span className="text-xs font-normal text-slate-400 font-sans ml-1">
                ({pageAnalysis.domMetrics?.iframesCount ?? pageAnalysis.iframes.length} iframes)
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {pageAnalysis.scripts.some(s => s.hasObfuscation || s.hasEval) ? (
                <span className="text-rose-400 font-medium">Obfuscated JS detected</span>
              ) : (
                'Standard scripts'
              )}
            </p>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Urgency Score</span>
            <Flame className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-slate-200">
              {Math.round(pageAnalysis.urgencyScore * 100)}%
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {pageAnalysis.urgencyScore > 0.4 ? (
                <span className="text-rose-400 font-medium">Social engineering panic language</span>
              ) : (
                'Low psychological urgency'
              )}
            </p>
          </div>
        </div>
      </div>

      {/* Redirect Chain Inspection */}
      {pageAnalysis.redirectChain && pageAnalysis.redirectChain.length > 0 && (
        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3">
          <div className="flex items-center space-x-2">
            <Globe className="w-4 h-4 text-indigo-400" />
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
              Redirect Chain Stepper ({pageAnalysis.redirectChain.length} Hops)
            </h4>
          </div>
          <div className="space-y-2">
            {pageAnalysis.redirectChain.map((hop, idx) => (
              <div key={idx} className="flex items-center space-x-2 text-xs font-mono bg-slate-950/60 p-2 rounded-lg border border-slate-800/60">
                <span className="px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 text-[10px] font-bold">
                  HOP {idx + 1} {hop.status && `[HTTP ${hop.status}]`}
                </span>
                <span className="text-slate-300 truncate flex-1">{hop.url}</span>
              </div>
            ))}
            <div className="flex items-center space-x-2 text-xs font-mono bg-emerald-950/20 p-2 rounded-lg border border-emerald-500/30">
              <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] font-bold">
                FINAL DESTINATION
              </span>
              <span className="text-emerald-300 truncate flex-1">{pageAnalysis.finalUrl}</span>
            </div>
          </div>
        </div>
      )}

      {/* Form Inspection Breakdown */}
      {pageAnalysis.forms && pageAnalysis.forms.length > 0 && (
        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <KeyRound className="w-4 h-4 text-amber-400" />
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
                Form &amp; Credential Inspection ({pageAnalysis.forms.length} forms)
              </h4>
            </div>
          </div>
          <div className="space-y-2.5">
            {pageAnalysis.forms.map((form, idx) => (
              <div
                key={idx}
                className={`p-3 rounded-lg border text-xs ${
                  form.hasPasswordField && (form.isCrossOrigin || form.isIpAction)
                    ? 'bg-rose-950/30 border-rose-500/40'
                    : 'bg-slate-950/50 border-slate-800'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1.5">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono font-bold text-slate-200">
                      {form.method} Form {form.name ? `(${form.name})` : `#${idx + 1}`}
                    </span>
                    {form.hasPasswordField && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                        Password Field
                      </span>
                    )}
                    {form.isCrossOrigin && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        Cross-Origin Action
                      </span>
                    )}
                    {form.isIpAction && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        IP Action Destination
                      </span>
                    )}
                  </div>
                  <span className="text-slate-500 font-mono text-[11px]">{form.inputCount} input fields</span>
                </div>
                <div className="font-mono text-[11px] text-slate-400 truncate">
                  <span className="text-slate-500">Destination: </span>
                  <span className={form.isCrossOrigin ? 'text-rose-300' : 'text-slate-300'}>
                    {form.actionResolved || form.action || '(Same Origin)'}
                  </span>
                </div>
                {form.description && (
                  <p className="text-[11px] text-slate-400 mt-1">{form.description}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Script & DOM Details */}
      {pageAnalysis.scripts && pageAnalysis.scripts.some(s => s.hasObfuscation || s.hasEval || s.hasDocumentWrite) && (
        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
              JavaScript Heuristic Detections
            </h4>
          </div>
          <div className="space-y-2">
            {pageAnalysis.scripts
              .filter(s => s.hasObfuscation || s.hasEval || s.hasDocumentWrite || s.hasSuspiciousRedirect)
              .map((script, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 text-xs">
                  <div className="flex items-center space-x-2 text-amber-400 font-medium mb-1">
                    <FileCode2 className="w-3.5 h-3.5" />
                    <span>Script #{idx + 1} {script.isExternal ? `(External: ${script.src})` : '(Inline Script)'}</span>
                  </div>
                  <ul className="list-disc list-inside text-slate-400 text-[11px] space-y-0.5">
                    {script.reasons.map((reason, rIdx) => (
                      <li key={rIdx}>{reason}</li>
                    ))}
                  </ul>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
};
