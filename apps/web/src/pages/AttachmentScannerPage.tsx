import React, { useState, useRef } from 'react';
import {
  FileText,
  Upload,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  ExternalLink,
  Copy,
  Check,
  Layers,
  Sparkles,
  FileCode,
  Globe,
  Info,
  RefreshCw,
  Mail,
  Hash
} from 'lucide-react';
import {
  AttachmentAnalysisResult,
  EmailAnalysisResult,
  RawIOCExtractionResult
} from '@phishnetra/shared';
import { api } from '../services/api';
import { Link } from 'react-router-dom';

const strToBase64 = (str: string): string => {
  return btoa(
    encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (_, p1) => {
      return String.fromCharCode(parseInt(p1, 16));
    })
  );
};

const SAMPLE_PRESETS = [
  {
    name: 'Urgent_Invoice_Overdue.pdf',
    type: 'PDF',
    description: 'Simulated PDF invoice containing an embedded URI hyperlink targeting an Office 365 credential harvester.',
    filename: 'Invoice_Overdue_October2026.pdf',
    contentBase64: strToBase64(
      `%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>\nendobj\n4 0 obj\n<< /Type /Annot /Subtype /Link /A << /Type /Action /S /URI /URI (https://login-microsoftonline-verify.ru/token) >> >>\nendobj\nxref\n0 5\n0000000000 65535 f\ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%%EOF`
    )
  },
  {
    name: 'M365_Password_Expiry.html',
    type: 'HTML',
    description: 'HTML attachment pretending to be an expired session notice with a credential harvest form.',
    filename: 'M365_Password_Expiry.html',
    contentBase64: strToBase64(
      `<!DOCTYPE html><html><head><title>Session Expired</title></head><body><h2>Your Microsoft 365 password expires today</h2><p>Click below to verify identity:</p><a href="https://secure-chase-update.top/auth/login.php?token=982471924">Verify Credentials Now</a><form action="http://198.51.100.42:8080/admin/chase-login.php" method="POST"><input type="password" name="pw"/><button type="submit">Submit</button></form></body></html>`
    )
  },
  {
    name: 'Benign_DocuSign_Contract.pdf',
    type: 'PDF',
    description: 'Clean PDF attachment referencing legitimate enterprise signature portal.',
    filename: 'DocuSign_Service_Agreement.pdf',
    contentBase64: strToBase64(
      `%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>\nendobj\n4 0 obj\n<< /Type /Annot /Subtype /Link /A << /Type /Action /S /URI /URI (https://docusign.com/terms) >> >>\nendobj\nxref\n0 5\n0000000000 65535 f\ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%%EOF`
    )
  },
  {
    name: 'Corporate_Security_Advisory.txt',
    type: 'TXT',
    description: 'Security advisory text containing defanged phishing indicators and active URLs.',
    filename: 'Advisory_FIN7_IOCs.txt',
    contentBase64: strToBase64(
      `Security Incident Advisory\nObserved command & control infrastructure:\nhxxps://login[.]paypal[.]com-verify-account[.]live/signin\nAlso visit https://example.com for benign verification.`
    )
  }
];

export const AttachmentScannerPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'attachment' | 'email_eml' | 'raw_ioc'>('attachment');
  const [selectedFile, setSelectedFile] = useState<{ filename: string; base64: string; size: number } | null>(null);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<AttachmentAnalysisResult | null>(null);
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // EML & Raw IOC state
  const [emlText, setEmlText] = useState<string>(
    `From: Security Alert <security@chase.com>\nSubject: URGENT: Verify Your Chase Online Access\nDate: Thu, 22 Oct 2026 10:00:00 +0000\nAuthentication-Results: spf=fail; dmarc=fail\n\nPlease verify your account immediately: https://secure-chase-update.top/auth/login.php`
  );
  const [emlResult, setEmlResult] = useState<EmailAnalysisResult | null>(null);
  const [rawText, setRawText] = useState<string>('hxxps://login[.]paypal[.]com-verify-account[.]live/signin');
  const [rawResult, setRawResult] = useState<RawIOCExtractionResult | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    readFile(file);
  };

  const readFile = (file: File) => {
    setErrorMsg(null);
    setResult(null);

    if (file.size > 10 * 1024 * 1024) {
      setErrorMsg('File exceeds 10MB limit. Please select an attachment smaller than 10MB.');
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const base64Data = (reader.result as string).split(',')[1] || '';
      setSelectedFile({
        filename: file.name,
        base64: base64Data,
        size: file.size
      });
    };
    reader.onerror = () => {
      setErrorMsg('Failed to read local file.');
    };
    reader.readAsDataURL(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      readFile(file);
    }
  };

  const handleApplyPreset = (preset: typeof SAMPLE_PRESETS[0]) => {
    setErrorMsg(null);
    setResult(null);
    const byteLength = atob(preset.contentBase64).length;
    setSelectedFile({
      filename: preset.filename,
      base64: preset.contentBase64,
      size: byteLength
    });
  };

  const handleAnalyzeAttachment = async () => {
    if (!selectedFile) {
      setErrorMsg('Please select or upload a supported attachment file first.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await api.analyzeAttachment({
        filename: selectedFile.filename,
        contentBase64: selectedFile.base64,
        maxUrlsToAnalyze: 25
      });
      setResult(res);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.message || err.message || 'Attachment analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyzeEml = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await api.analyzeEmail({
        rawEmlText: emlText,
        evaluateExtractedUrls: true
      });
      setEmlResult(res);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.message || err.message || 'Email analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyzeRawIOC = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await api.extractRawIOCs(rawText);
      setRawResult(res);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.message || err.message || 'IOC extraction failed.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedUrl(text);
    setTimeout(() => setCopiedUrl(null), 2000);
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 animate-fadeIn">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 p-6 sm:p-8 shadow-xl">
        <div className="space-y-2">
          <div className="flex items-center space-x-2.5">
            <span className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <FileText className="w-5 h-5" />
            </span>
            <span className="text-xs font-mono font-semibold tracking-wider text-indigo-400 uppercase">
              Semester 1 Vertical Slice • Safe Attachment Link Extraction &amp; Threat Evaluation
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Email Attachment & Embedded Link Scanner
          </h1>
          <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
            Safely unpacks email attachments (PDF, HTML, DOCX, TXT, and EML) without executing active code.
            Extracts all embedded action hyperlinks, URI dictionaries, and hidden destinations, and evaluates each target
            through PhishNetra&apos;s Zero-Trust multi-layer detection pipeline.
          </p>
        </div>

        {/* Tab Selector */}
        <div className="mt-6 flex flex-wrap gap-2 border-b border-slate-800/80 pb-3">
          <button
            onClick={() => setActiveTab('attachment')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all ${
              activeTab === 'attachment'
                ? 'bg-indigo-500 text-white shadow-md shadow-indigo-500/20'
                : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <Upload className="w-4 h-4" />
            <span>Attachment File Upload (PDF, HTML, DOCX, TXT)</span>
          </button>

          <button
            onClick={() => setActiveTab('email_eml')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all ${
              activeTab === 'email_eml'
                ? 'bg-indigo-500 text-white shadow-md shadow-indigo-500/20'
                : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <Mail className="w-4 h-4" />
            <span>RFC 822 Email Parser (Headers & SPF/DMARC)</span>
          </button>

          <button
            onClick={() => setActiveTab('raw_ioc')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all ${
              activeTab === 'raw_ioc'
                ? 'bg-indigo-500 text-white shadow-md shadow-indigo-500/20'
                : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <Hash className="w-4 h-4" />
            <span>Raw Text IOC & Defanger</span>
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center space-x-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Mode 1: File Attachment Analysis */}
      {activeTab === 'attachment' && (
        <div className="space-y-6">
          {/* Presets Bar */}
          <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-2">
            <div className="flex items-center space-x-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
              <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
              <span>Quick Test Presets (Ready for Demonstration)</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 pt-1">
              {SAMPLE_PRESETS.map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleApplyPreset(preset)}
                  className="p-3 rounded-xl bg-slate-950 hover:bg-slate-900 border border-slate-800/90 text-left transition-all group flex flex-col justify-between"
                >
                  <div className="flex items-center justify-between w-full mb-1">
                    <span className="text-xs font-bold text-white group-hover:text-indigo-400 truncate">
                      {preset.name}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                      {preset.type}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">{preset.description}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Upload Dropzone */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-2xl p-8 sm:p-12 text-center cursor-pointer transition-all ${
              isDragging
                ? 'border-indigo-400 bg-indigo-500/10'
                : selectedFile
                ? 'border-emerald-500/50 bg-emerald-500/5'
                : 'border-slate-800 hover:border-slate-700 bg-slate-950/60'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pdf,.html,.htm,.txt,.docx,.eml"
              onChange={handleFileChange}
              className="hidden"
            />
            <div className="flex flex-col items-center space-y-3">
              <div className="p-3.5 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
                <Upload className="w-6 h-6 animate-pulse" />
              </div>

              {selectedFile ? (
                <div>
                  <h3 className="text-sm font-bold text-emerald-400 font-mono">{selectedFile.filename}</h3>
                  <p className="text-xs text-slate-400 mt-1">
                    {(selectedFile.size / 1024).toFixed(1)} KB • File ready for extraction & deep link inspection
                  </p>
                </div>
              ) : (
                <div>
                  <h3 className="text-sm font-bold text-white">Drag & drop email attachment here, or click to browse</h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Supported formats: <span className="text-indigo-300 font-mono font-semibold">.PDF</span>,{' '}
                    <span className="text-indigo-300 font-mono font-semibold">.HTML</span>,{' '}
                    <span className="text-indigo-300 font-mono font-semibold">.DOCX</span>,{' '}
                    <span className="text-indigo-300 font-mono font-semibold">.TXT</span>,{' '}
                    <span className="text-indigo-300 font-mono font-semibold">.EML</span> (Max 10 MB)
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Action Trigger */}
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">
              Files are evaluated in-memory without binary execution or macro activation.
            </span>
            <button
              type="button"
              disabled={!selectedFile || loading}
              onClick={handleAnalyzeAttachment}
              className={`px-6 py-2.5 rounded-xl font-bold text-xs flex items-center space-x-2 transition-all ${
                !selectedFile || loading
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-gradient-to-r from-indigo-500 to-cyan-500 hover:from-indigo-400 hover:to-cyan-400 text-slate-950 shadow-lg shadow-indigo-500/25 active:scale-[0.98]'
              }`}
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Extracting & Evaluating Embedded URLs...</span>
                </>
              ) : (
                <>
                  <Layers className="w-4 h-4" />
                  <span>Execute Attachment Threat Scan</span>
                </>
              )}
            </button>
          </div>

          {/* Attachment Scan Result Display */}
          {result && (
            <div className="space-y-6 pt-2 animate-fadeIn">
              {/* Verdict Summary Card */}
              <div
                className={`p-6 sm:p-8 rounded-2xl border shadow-xl ${
                  result.processingStatus === 'THREATS_DETECTED'
                    ? 'bg-rose-950/20 border-rose-500/40'
                    : result.processingStatus === 'NO_SUSPICIOUS_URLS_FOUND'
                    ? 'bg-emerald-950/20 border-emerald-500/40'
                    : 'bg-amber-950/20 border-amber-500/40'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800/80 pb-4">
                  <div className="flex items-center space-x-3">
                    {result.processingStatus === 'THREATS_DETECTED' ? (
                      <span className="p-3 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-400">
                        <ShieldAlert className="w-6 h-6" />
                      </span>
                    ) : result.processingStatus === 'NO_SUSPICIOUS_URLS_FOUND' ? (
                      <span className="p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                        <ShieldCheck className="w-6 h-6" />
                      </span>
                    ) : (
                      <span className="p-3 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
                        <AlertTriangle className="w-6 h-6" />
                      </span>
                    )}

                    <div>
                      <div className="text-xs font-mono text-slate-400">
                        Attachment Report #{result.analysisId.slice(0, 12)} • {new Date(result.analyzedAt).toLocaleTimeString()}
                      </div>
                      <h2 className="text-xl font-extrabold text-white font-mono mt-0.5">{result.filename}</h2>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <span className="px-2.5 py-1 rounded-lg text-xs font-mono font-bold bg-slate-900 border border-slate-800 text-slate-300">
                      {result.detectedFormat}
                    </span>
                    <span
                      className={`px-3 py-1 rounded-xl text-xs font-bold font-mono border ${
                        result.overallVerdict === 'PHISHING'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : result.overallVerdict === 'SUSPICIOUS'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      }`}
                    >
                      {result.processingStatus === 'THREATS_DETECTED'
                        ? 'MALICIOUS URLS FOUND'
                        : result.processingStatus === 'NO_SUSPICIOUS_URLS_FOUND'
                        ? 'NO THREATS DETECTED'
                        : 'UNABLE TO FULLY PARSE'}
                    </span>
                  </div>
                </div>

                {/* KPI Metrics */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-6">
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Total URLs Found</span>
                    <div className="text-lg font-bold text-white font-mono mt-0.5">
                      {result.totalUrlsExtracted}
                    </div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Unique Targets Evaluated</span>
                    <div className="text-lg font-bold text-cyan-400 font-mono mt-0.5">
                      {result.uniqueUrlsExtracted}
                    </div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Flagged Threats</span>
                    <div
                      className={`text-lg font-bold font-mono mt-0.5 ${
                        result.suspiciousOrMaliciousUrls.length > 0 ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {result.suspiciousOrMaliciousUrls.length}
                    </div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Peak Risk Score</span>
                    <div
                      className={`text-lg font-bold font-mono mt-0.5 ${
                        result.overallRiskScore >= 75
                          ? 'text-rose-400'
                          : result.overallRiskScore >= 45
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {result.overallRiskScore} / 100
                    </div>
                  </div>
                </div>

                {/* Evidence Findings */}
                {result.evidenceReasons.length > 0 && (
                  <div className="mt-5 space-y-1.5 pt-4 border-t border-slate-800/80">
                    <span className="text-xs font-mono font-semibold text-slate-300 uppercase">
                      Detection Evidence:
                    </span>
                    <ul className="space-y-1">
                      {result.evidenceReasons.map((reason, i) => (
                        <li key={i} className="text-xs text-slate-300 flex items-start space-x-2">
                          <span className="text-indigo-400 mt-0.5">•</span>
                          <span>{reason}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Warnings */}
                {result.warningNotes.length > 0 && (
                  <div className="mt-4 p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs space-y-1">
                    {result.warningNotes.map((warn, i) => (
                      <div key={i} className="flex items-center space-x-2">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                        <span>{warn}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Extracted URLs Table */}
              {result.analyzedUrls.length > 0 && (
                <div className="glass-panel p-6 rounded-2xl border-slate-800 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2 text-sm font-bold text-white font-mono">
                      <Globe className="w-4 h-4 text-cyan-400" />
                      <span>Extracted Embedded URLs ({result.analyzedUrls.length})</span>
                    </div>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                          <th className="pb-3 font-semibold">Extracted Hyperlink Target</th>
                          <th className="pb-3 font-semibold">Verdict</th>
                          <th className="pb-3 font-semibold">Risk Score</th>
                          <th className="pb-3 font-semibold">Confidence</th>
                          <th className="pb-3 font-semibold text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono">
                        {result.analyzedUrls.map((item, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                            <td className="py-3 pr-4 max-w-md truncate text-slate-200">
                              <span className="select-all">{item.url}</span>
                            </td>
                            <td className="py-3 pr-4">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  item.verdict === 'PHISHING'
                                    ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                                    : item.verdict === 'SUSPICIOUS'
                                    ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                                    : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                                }`}
                              >
                                {item.verdict}
                              </span>
                            </td>
                            <td className="py-3 pr-4">
                              <span
                                className={`font-bold ${
                                  item.riskScore >= 75
                                    ? 'text-rose-400'
                                    : item.riskScore >= 45
                                    ? 'text-amber-400'
                                    : 'text-emerald-400'
                                }`}
                              >
                                {item.riskScore}
                              </span>
                              <span className="text-slate-500 text-[10px]">/100</span>
                            </td>
                            <td className="py-3 pr-4 text-slate-300">
                              {(item.confidence * 100).toFixed(0)}%
                            </td>
                            <td className="py-3 text-right">
                              <div className="flex items-center justify-end space-x-2">
                                <button
                                  type="button"
                                  onClick={() => copyToClipboard(item.url)}
                                  className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
                                  title="Copy URL"
                                >
                                  {copiedUrl === item.url ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3.5 h-3.5" />
                                  )}
                                </button>
                                <Link
                                  to={`/analyze/${item.id}`}
                                  className="p-1 rounded hover:bg-slate-800 text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                                  title="Inspect Full Multi-Layer Evidence"
                                >
                                  <ExternalLink className="w-3.5 h-3.5" />
                                </Link>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Disclaimer */}
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 text-[11px] text-slate-400 flex items-start space-x-2">
                <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                <span>{result.disclaimer}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Mode 2: RFC 822 EML Analysis */}
      {activeTab === 'email_eml' && (
        <div className="space-y-6">
          <div className="glass-panel p-6 rounded-2xl border-slate-800 space-y-4">
            <label className="text-xs font-mono font-semibold text-slate-300 uppercase">
              Raw RFC 822 Email Message (Headers + Body)
            </label>
            <textarea
              rows={10}
              value={emlText}
              onChange={e => setEmlText(e.target.value)}
              className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              placeholder="Paste RFC 822 EML message here..."
            />
            <div className="flex justify-end">
              <button
                type="button"
                disabled={loading}
                onClick={handleAnalyzeEml}
                className="px-6 py-2.5 rounded-xl bg-indigo-500 hover:bg-indigo-400 text-white font-bold text-xs flex items-center space-x-2"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Mail className="w-4 h-4" />}
                <span>Inspect Email & Verify Spoofing</span>
              </button>
            </div>
          </div>

          {emlResult && (
            <div className="glass-panel p-6 rounded-2xl border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="text-sm font-bold text-white font-mono">Email Analysis Report</span>
                <span
                  className={`px-3 py-1 rounded-xl text-xs font-bold font-mono border ${
                    emlResult.verdict === 'PHISHING'
                      ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                      : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                  }`}
                >
                  {emlResult.verdict} ({emlResult.phishingScore}/100)
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-400 font-mono">SPF Status</span>
                  <div className="text-sm font-bold font-mono text-white mt-0.5">{emlResult.headers.spfStatus}</div>
                </div>
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-400 font-mono">DMARC Status</span>
                  <div className="text-sm font-bold font-mono text-white mt-0.5">{emlResult.headers.dmarcStatus}</div>
                </div>
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-400 font-mono">Sender Spoofed</span>
                  <div className={`text-sm font-bold font-mono mt-0.5 ${emlResult.headers.isSpoofed ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {emlResult.headers.isSpoofed ? 'YES (Domain Mismatch)' : 'NO'}
                  </div>
                </div>
              </div>

              {emlResult.evidenceReasons.length > 0 && (
                <div className="pt-2">
                  <span className="text-xs font-semibold text-slate-400 font-mono uppercase">Evidence:</span>
                  <ul className="mt-1 space-y-1">
                    {emlResult.evidenceReasons.map((r, idx) => (
                      <li key={idx} className="text-xs text-slate-300 flex items-start space-x-2">
                        <span className="text-indigo-400">•</span>
                        <span>{r}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Mode 3: Raw IOC Text Defanger */}
      {activeTab === 'raw_ioc' && (
        <div className="space-y-6">
          <div className="glass-panel p-6 rounded-2xl border-slate-800 space-y-4">
            <label className="text-xs font-mono font-semibold text-slate-300 uppercase">
              Raw Threat Advisory / Defanged IOC Input
            </label>
            <textarea
              rows={8}
              value={rawText}
              onChange={e => setRawText(e.target.value)}
              className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              placeholder="Paste unstructured threat text with hxxp:// or [.] ..."
            />
            <div className="flex justify-end">
              <button
                type="button"
                disabled={loading}
                onClick={handleAnalyzeRawIOC}
                className="px-6 py-2.5 rounded-xl bg-indigo-500 hover:bg-indigo-400 text-white font-bold text-xs flex items-center space-x-2"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Hash className="w-4 h-4" />}
                <span>Extract & Refang IOCs</span>
              </button>
            </div>
          </div>

          {rawResult && (
            <div className="glass-panel p-6 rounded-2xl border-slate-800 space-y-4">
              <span className="text-sm font-bold text-white font-mono">
                Extracted Indicators ({rawResult.totalExtracted})
              </span>
              <div className="space-y-2">
                {rawResult.urls.map((u, i) => (
                  <div key={i} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs font-mono">
                    <span className="text-cyan-400 truncate pr-2">{u}</span>
                    <button onClick={() => copyToClipboard(u)} className="p-1 hover:text-white text-slate-400">
                      {copiedUrl === u ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default AttachmentScannerPage;
