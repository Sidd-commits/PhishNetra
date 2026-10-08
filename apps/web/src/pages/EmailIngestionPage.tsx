import React, { useState } from 'react';
import {
  Mail,
  FileCode,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Check,
  Play,
  RefreshCw,
  Hash,
  Globe,
  Server,
  ExternalLink,
  Lock,
  Search
} from 'lucide-react';
import { EmailAnalysisResult, RawIOCExtractionResult } from '@phishnetra/shared';
import { api } from '../services/api';

const SAMPLE_PHISHING_EMAIL = `From: Security Alert <security@chase.com>
Reply-To: security-verify@rogue-inbox.com
Return-Path: no-reply@attacker-mailer.xyz
Subject: URGENT: Your Chase Online Access Has Been Temporarily Suspended
Date: Thu, 08 Oct 2026 11:30:00 +0000
Authentication-Results: spf=fail (sender IP 198.51.100.25); dkim=none; dmarc=fail (p=reject)

Dear Valued Customer,

We detected an unauthorized sign-in attempt from an unrecognized IP address (192.168.1.100).
To protect your accounts and restore full access, please verify your identity immediately:

https://secure-chase-update.top/auth/login.php?token=982471924

Failure to verify within 24 hours will result in permanent account suspension.

Sincerely,
Chase Fraud Prevention Center
`;

const SAMPLE_THREAT_REPORT = `[THREAT ADVISORY - APT-38 FIN6 FINANCIAL CLUSTER]
Observed command & control infrastructure hosting credential harvesting portals:
hxxps://login[.]paypal[.]com-verify-account[.]live/signin
hxxp://198.51.100.42:8080/admin/chase-login[.]php
Originating Mailer Server IP: 198.51.100.25
Malware Dropper SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Contact Phisher: attacker-ops@shadow-corp[.]top
`;

export const EmailIngestionPage: React.FC = () => {
  const [activeMode, setActiveMode] = useState<'email' | 'raw_ioc'>('email');
  const [inputText, setInputText] = useState<string>(SAMPLE_PHISHING_EMAIL);
  const [analyzing, setAnalyzing] = useState<boolean>(false);

  const [emailResult, setEmailResult] = useState<EmailAnalysisResult | null>(null);
  const [rawResult, setRawResult] = useState<RawIOCExtractionResult | null>(null);
  const [copiedIocs, setCopiedIocs] = useState<boolean>(false);

  const handleAnalyze = async () => {
    if (!inputText.trim()) return;

    try {
      setAnalyzing(true);
      if (activeMode === 'email') {
        const res = await api.analyzeEmail({
          rawEmlText: inputText,
          evaluateExtractedUrls: true
        });
        setEmailResult(res);
        setRawResult(null);
      } else {
        const res = await api.extractRawIOCs(inputText);
        setRawResult(res);
        setEmailResult(null);
      }
    } catch (err: any) {
      alert(`Analysis failed: ${err.message}`);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleCopyAllIOCs = () => {
    if (emailResult) {
      const all = emailResult.extractedIocs.map(i => `${i.type}: ${i.value}`).join('\n');
      navigator.clipboard.writeText(all);
      setCopiedIocs(true);
      setTimeout(() => setCopiedIocs(false), 2000);
    } else if (rawResult) {
      const all = [
        ...rawResult.urls.map(u => `URL: ${u}`),
        ...rawResult.domains.map(d => `DOMAIN: ${d}`),
        ...rawResult.ips.map(ip => `IP: ${ip}`),
        ...rawResult.emails.map(e => `EMAIL: ${e}`),
        ...rawResult.hashes.map(h => `HASH: ${h}`)
      ].join('\n');
      navigator.clipboard.writeText(all);
      setCopiedIocs(true);
      setTimeout(() => setCopiedIocs(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 backdrop-blur-md relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <span className="p-2 bg-purple-500/10 border border-purple-500/30 rounded-lg text-purple-400">
                <Mail className="w-6 h-6" />
              </span>
              <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
                Email Phishing Parser & Raw IOC Ingestion
              </h1>
            </div>
            <p className="text-slate-400 text-sm">
              Inspect raw RFC 822 email headers, verify SPF/DKIM/DMARC spoofing indicators, extract defanged IOCs (hxxp, [.]), and scan embedded links in parallel.
            </p>
          </div>

          {/* Mode Switcher */}
          <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => {
                setActiveMode('email');
                setInputText(SAMPLE_PHISHING_EMAIL);
              }}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                activeMode === 'email' ? 'bg-purple-500/20 text-purple-300 shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Raw Email (.EML)
            </button>
            <button
              onClick={() => {
                setActiveMode('raw_ioc');
                setInputText(SAMPLE_THREAT_REPORT);
              }}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                activeMode === 'raw_ioc' ? 'bg-purple-500/20 text-purple-300 shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Unstructured Text / IOCs
            </button>
          </div>
        </div>
      </div>

      {/* Input Workbench */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            {activeMode === 'email' ? 'Raw RFC 822 Email Headers & Body' : 'Paste Unstructured Threat Report / Ticket Text'}
          </label>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setInputText(activeMode === 'email' ? SAMPLE_PHISHING_EMAIL : SAMPLE_THREAT_REPORT)}
              className="text-xs text-purple-400 hover:underline font-mono"
            >
              Load Sample Data
            </button>
            <button
              onClick={() => setInputText('')}
              className="text-xs text-slate-500 hover:text-slate-300 font-mono"
            >
              Clear
            </button>
          </div>
        </div>

        <textarea
          rows={10}
          value={inputText}
          onChange={e => setInputText(e.target.value)}
          placeholder={activeMode === 'email' ? 'From: sender@domain.com\nSubject: ...' : 'Paste text containing hxxp://, IPs, hashes...'}
          className="w-full bg-slate-950 border border-slate-800 rounded-lg p-4 text-xs font-mono text-slate-200 focus:outline-none focus:border-purple-500 resize-y leading-relaxed"
        />

        <div className="flex items-center justify-end">
          <button
            onClick={handleAnalyze}
            disabled={analyzing || !inputText.trim()}
            className="flex items-center gap-2 bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-400 hover:to-indigo-500 text-slate-950 font-semibold px-6 py-2.5 rounded-lg text-sm transition-all disabled:opacity-50"
          >
            {analyzing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
            <span>{activeMode === 'email' ? 'Parse & Scan Email' : 'Extract Defanged IOCs'}</span>
          </button>
        </div>
      </div>

      {/* Email Analysis Output */}
      {emailResult && (
        <div className="space-y-6">
          {/* Email Verdict Banner */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">SUBJECT</div>
                <div className="text-base font-bold text-slate-100">{emailResult.headers.subject}</div>
              </div>

              <div className="flex items-center gap-4">
                <div>
                  <div className="text-xs text-slate-400 font-mono">PHISHING RISK SCORE</div>
                  <div className={`text-2xl font-bold font-mono ${
                    emailResult.phishingScore >= 75 ? 'text-red-400' : (emailResult.phishingScore >= 45 ? 'text-amber-400' : 'text-emerald-400')
                  }`}>
                    {emailResult.phishingScore}/100
                  </div>
                </div>

                <div>
                  <div className="text-xs text-slate-400 font-mono">EMAIL VERDICT</div>
                  <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold ${
                    emailResult.verdict === 'PHISHING'
                      ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                      : (emailResult.verdict === 'SUSPICIOUS'
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30')
                  }`}>
                    {emailResult.verdict === 'PHISHING' ? <AlertTriangle className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                    {emailResult.verdict}
                  </span>
                </div>
              </div>
            </div>

            {/* Authentication & Spoof Header Matrix */}
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 mt-4">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="text-[10px] text-slate-500 font-mono uppercase">FROM ADDRESS</div>
                <div className="text-xs font-mono text-slate-200 truncate mt-0.5" title={emailResult.headers.from}>
                  {emailResult.headers.from}
                </div>
              </div>

              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="text-[10px] text-slate-500 font-mono uppercase">SPF STATUS</div>
                <div className={`text-xs font-bold font-mono mt-0.5 ${
                  emailResult.headers.spfStatus === 'PASS' ? 'text-emerald-400' : (emailResult.headers.spfStatus === 'FAIL' ? 'text-red-400' : 'text-slate-400')
                }`}>
                  {emailResult.headers.spfStatus}
                </div>
              </div>

              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="text-[10px] text-slate-500 font-mono uppercase">DMARC STATUS</div>
                <div className={`text-xs font-bold font-mono mt-0.5 ${
                  emailResult.headers.dmarcStatus === 'PASS' ? 'text-emerald-400' : (emailResult.headers.dmarcStatus === 'FAIL' ? 'text-red-400' : 'text-slate-400')
                }`}>
                  {emailResult.headers.dmarcStatus}
                </div>
              </div>

              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div className="text-[10px] text-slate-500 font-mono uppercase">SPOOFED SENDER</div>
                <div className={`text-xs font-bold font-mono mt-0.5 ${
                  emailResult.headers.isSpoofed ? 'text-red-400' : 'text-emerald-400'
                }`}>
                  {emailResult.headers.isSpoofed ? 'YES (FLAGGED)' : 'NO'}
                </div>
              </div>
            </div>

            {/* Findings Bullet Points */}
            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 mt-4">
              <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Identified Security Evidence
              </div>
              <ul className="space-y-1.5 text-xs text-slate-300 font-mono">
                {emailResult.evidenceReasons.map((r, i) => (
                  <li key={i} className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Embedded Scanned URLs */}
          {emailResult.analyzedUrls.length > 0 && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
              <h3 className="text-base font-semibold text-slate-100 mb-4">
                Embedded URLs & Multi-Layer Deep Scan Results
              </h3>
              <div className="space-y-2">
                {emailResult.analyzedUrls.map((u, i) => (
                  <div key={i} className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 flex items-center justify-between">
                    <div className="max-w-lg truncate">
                      <div className="text-xs font-mono text-cyan-300 truncate" title={u.url}>
                        {u.url}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                        Scan ID: {u.id}
                      </div>
                    </div>

                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <div className="text-[10px] text-slate-500 font-mono">RISK SCORE</div>
                        <div className="text-xs font-bold text-red-400 font-mono">{u.riskScore}/100</div>
                      </div>
                      <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                        u.verdict === 'PHISHING' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {u.verdict}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Raw IOC Extraction Output */}
      {rawResult && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-base font-bold text-slate-100">
                Extracted & Defanged IOCs ({rawResult.totalExtracted})
              </h3>
              <p className="text-xs text-slate-400">
                Normalized URLs, IP addresses, domains, and cryptographic hashes extracted from raw unstructured content.
              </p>
            </div>
            <button
              onClick={handleCopyAllIOCs}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-200 rounded-lg text-xs font-mono"
            >
              {copiedIocs ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedIocs ? 'Copied All' : 'Copy All IOCs'}</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
              <div className="text-xs font-semibold text-purple-400 font-mono">URLS ({rawResult.urls.length})</div>
              <ul className="space-y-1 text-xs font-mono text-slate-300 max-h-48 overflow-y-auto">
                {rawResult.urls.map((u, i) => (
                  <li key={i} className="truncate" title={u}>• {u}</li>
                ))}
              </ul>
            </div>

            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
              <div className="text-xs font-semibold text-cyan-400 font-mono">DOMAINS ({rawResult.domains.length})</div>
              <ul className="space-y-1 text-xs font-mono text-slate-300 max-h-48 overflow-y-auto">
                {rawResult.domains.map((d, i) => (
                  <li key={i}>• {d}</li>
                ))}
              </ul>
            </div>

            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
              <div className="text-xs font-semibold text-blue-400 font-mono">IP ADDRESSES ({rawResult.ips.length})</div>
              <ul className="space-y-1 text-xs font-mono text-slate-300 max-h-48 overflow-y-auto">
                {rawResult.ips.map((ip, i) => (
                  <li key={i}>• {ip}</li>
                ))}
              </ul>
            </div>

            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
              <div className="text-xs font-semibold text-amber-400 font-mono">HASHES ({rawResult.hashes.length})</div>
              <ul className="space-y-1 text-xs font-mono text-slate-300 max-h-48 overflow-y-auto">
                {rawResult.hashes.map((h, i) => (
                  <li key={i} className="truncate" title={h}>• {h}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
