import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { QuishingScanResult } from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  QrCode,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Zap,
  Lock,
  Terminal,
  ExternalLink,
  Copy,
  Check,
  RefreshCw,
  Search,
  Eye,
  Camera,
  FileText
} from 'lucide-react';

export const QuishingDefensePage: React.FC = () => {
  const { showToast } = useToast();
  const [imageUrl, setImageUrl] = useState('');
  const [rawText, setRawText] = useState('');
  const [deepScanPayload, setDeepScanPayload] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<QuishingScanResult | null>(null);
  const [samples, setSamples] = useState<Array<{ title: string; imageUrl: string; rawText: string; targetedBrand: string }>>([]);
  const [copiedRule, setCopiedRule] = useState(false);

  useEffect(() => {
    loadSamples();
  }, []);

  const loadSamples = async () => {
    try {
      const data = await api.getQuishingSamples();
      setSamples(data);
    } catch {
      // Fallback presets if offline
      setSamples([
        {
          title: 'MFA Authenticator Reset Lure',
          imageUrl: 'https://cdn.phishnetra.internal/samples/qr-okta-mfa-reset.png',
          rawText: 'Scan to update your Authenticator app now to avoid immediate account suspension',
          targetedBrand: 'Okta'
        },
        {
          title: 'Microsoft 365 Password Expiry Lure',
          imageUrl: 'https://cdn.phishnetra.internal/samples/qr-m365-expiry.png',
          rawText: 'Microsoft 365 security alert: Session expired. Scan QR barcode with mobile device.',
          targetedBrand: 'Microsoft 365'
        }
      ]);
    }
  };

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!imageUrl.trim() && !rawText.trim()) {
      showToast('warning', 'Missing Input', 'Provide an image URL, barcode reference, or lure text to inspect.');
      return;
    }

    setScanning(true);
    try {
      const result = await api.scanQuishing({
        imageUrl: imageUrl.trim() || undefined,
        rawText: rawText.trim() || undefined,
        deepScanPayload,
        ocrExtract: true
      });
      setScanResult(result);
      showToast(
        result.isQuishingAttack ? 'threat' : 'info',
        `Scan complete: ${result.verdict}`,
        `Risk Score: ${result.riskScore} / 100`
      );
    } catch (err: any) {
      showToast('error', 'Quishing scan failed', err.message);
    } finally {
      setScanning(false);
    }
  };

  const handleApplySample = (sample: { imageUrl: string; rawText: string }) => {
    setImageUrl(sample.imageUrl);
    setRawText(sample.rawText);
    showToast('info', 'Preset Loaded', 'Loaded preset quishing sample');
  };

  const copySnortRule = () => {
    if (scanResult?.mitigationPayload?.snortRule) {
      navigator.clipboard.writeText(scanResult.mitigationPayload.snortRule);
      setCopiedRule(true);
      showToast('success', 'Copied to Clipboard', 'Snort NIDS rule copied to clipboard');
      setTimeout(() => setCopiedRule(false), 2000);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-emerald-950/70 via-slate-900 to-slate-900 border border-emerald-500/20 p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <QrCode className="w-5 h-5" />
              </div>
              <h1 className="text-xl font-bold text-white tracking-wide">
                Multimodal Quishing (QR Code) Defense
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-full font-semibold">
                Milestone 17
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-400 max-w-2xl leading-relaxed">
              Detects and neutralizes QR-code phishing (Quishing) vectors designed to bypass secure email gateways (SEG). Decodes embedded barcodes, unmasks dynamic shorteners, extracts OCR visual lures, and issues automated Passkey/FIDO2 defense challenges.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => {
                setImageUrl('https://identity-access-update.qrco.de/mfa-stepup');
                setRawText('Urgent: Microsoft 365 Authenticator upgrade required. Scan QR barcode with phone.');
              }}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors flex items-center space-x-1.5"
            >
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span>Load Threat Lure</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid: Form & Preset Samples */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Scan Request Form */}
        <div className="lg:col-span-2 space-y-6">
          <form onSubmit={handleScan} className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center space-x-2">
              <Camera className="w-4 h-4 text-emerald-400" />
              <span>Multimodal Ingestion & Barcode Analyzer</span>
            </h2>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  QR Image URL or Barcode Source
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={imageUrl}
                    onChange={(e) => setImageUrl(e.target.value)}
                    placeholder="https://example.com/qr-invoice.png or data:image/png;base64,..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                  {imageUrl && (
                    <button
                      type="button"
                      onClick={() => setImageUrl('')}
                      className="absolute right-2.5 top-2.5 text-slate-500 hover:text-slate-300 text-xs"
                    >
                      Clear
                    </button>
                  )}
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  Accompanying Document / Email Text (Visual OCR Context)
                </label>
                <textarea
                  rows={3}
                  value={rawText}
                  onChange={(e) => setRawText(e.target.value)}
                  placeholder="Paste OCR text, email subject line, or image caption (e.g. 'Scan to upgrade your MFA Authenticator app now...')"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div className="flex items-center space-x-2 pt-1">
                <input
                  type="checkbox"
                  id="deepScan"
                  checked={deepScanPayload}
                  onChange={(e) => setDeepScanPayload(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-500 h-3.5 w-3.5"
                />
                <label htmlFor="deepScan" className="text-xs text-slate-300 cursor-pointer">
                  Execute 8-layer deep scan on unmasked destination URL
                </label>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={scanning}
                className="px-4 py-2 rounded-xl text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition-colors flex items-center space-x-2 shadow-lg shadow-emerald-500/20 disabled:opacity-50"
              >
                {scanning ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Analyzing Multimodal Payload...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-3.5 h-3.5" />
                    <span>Scan & Unmask Barcode</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Scan Results Panel */}
          {scanResult && (
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-5 animate-in fade-in duration-300">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-wider ${
                        scanResult.verdict === 'PHISHING'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : scanResult.verdict === 'SUSPICIOUS'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      }`}
                    >
                      {scanResult.verdict}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      Risk Score: {scanResult.riskScore} / 100
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-2 font-medium">
                    {scanResult.recommendedAction}
                  </p>
                </div>

                <div className="text-right">
                  <span className="text-[10px] font-mono text-slate-500 block">Scan ID: {scanResult.scanId}</span>
                  <span className="text-[10px] font-mono text-slate-500 block">
                    {new Date(scanResult.scannedAt).toLocaleTimeString()}
                  </span>
                </div>
              </div>

              {/* QR Metadata & Destination */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-3.5 space-y-2">
                  <span className="text-[10px] font-mono uppercase text-slate-500">Decoded Destination Payload</span>
                  {scanResult.extractedUrls.length > 0 ? (
                    scanResult.extractedUrls.map((url, idx) => (
                      <div key={idx} className="flex items-center space-x-2 text-xs font-mono text-cyan-300 break-all">
                        <ExternalLink className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span>{url}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500">No external URL links found</div>
                  )}

                  {scanResult.qrMetadata && (
                    <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
                      <span>Format: {scanResult.qrMetadata.format}</span>
                      <span className={scanResult.qrMetadata.isDynamicOrTracking ? 'text-amber-400 font-semibold' : 'text-slate-400'}>
                        {scanResult.qrMetadata.isDynamicOrTracking ? 'Dynamic Shortener Alert' : 'Direct Link'}
                      </span>
                    </div>
                  )}
                </div>

                {/* Visual Lures & OCR Extraction */}
                <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-3.5 space-y-2">
                  <span className="text-[10px] font-mono uppercase text-slate-500">Visual Lures & Urgency Markers</span>
                  {scanResult.visualLures.length > 0 ? (
                    scanResult.visualLures.map((lure, idx) => (
                      <div key={idx} className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-rose-300">{lure.urgencyCategory}</span>
                          {lure.brandTargeted && (
                            <span className="text-[10px] font-mono text-indigo-400 bg-indigo-500/10 px-1.5 py-0.5 rounded">
                              Target: {lure.brandTargeted}
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 font-mono italic">"{lure.text}"</p>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500">No urgency lures detected</div>
                  )}
                </div>
              </div>

              {/* Autonomous Defenses & Snort Rule */}
              {scanResult.mitigationPayload && (
                <div className="space-y-3 pt-2 border-t border-slate-800">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-white flex items-center space-x-1.5">
                      <Terminal className="w-4 h-4 text-emerald-400" />
                      <span>Autonomous Gateway Countermeasures</span>
                    </span>

                    <div className="flex items-center space-x-2">
                      {scanResult.mitigationPayload.fido2Enforced && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center space-x-1">
                          <Lock className="w-2.5 h-2.5" />
                          <span>FIDO2 Passkey Enforced</span>
                        </span>
                      )}
                      {scanResult.mitigationPayload.qrBlockedAtGateway && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center space-x-1">
                          <ShieldAlert className="w-2.5 h-2.5" />
                          <span>QR Ingress Blocked</span>
                        </span>
                      )}
                    </div>
                  </div>

                  {scanResult.mitigationPayload.snortRule && (
                    <div className="relative">
                      <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
                        {scanResult.mitigationPayload.snortRule}
                      </pre>
                      <button
                        onClick={copySnortRule}
                        className="absolute right-2.5 top-2.5 p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors text-xs flex items-center space-x-1"
                      >
                        {copiedRule ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedRule ? 'Copied' : 'Copy Rule'}</span>
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column: Threat Presets & Threat Intel Card */}
        <div className="space-y-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
            <h3 className="text-xs font-semibold uppercase text-slate-400 tracking-wider flex items-center space-x-2">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span>Quishing Campaign Scenarios</span>
            </h3>

            <div className="space-y-2.5">
              {samples.map((sample, idx) => (
                <div
                  key={idx}
                  onClick={() => handleApplySample(sample)}
                  className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-emerald-500/40 hover:bg-slate-900 transition-all cursor-pointer group space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-200 group-hover:text-emerald-300">
                      {sample.title}
                    </span>
                    <span className="text-[10px] font-mono text-indigo-400 bg-indigo-500/10 px-1.5 py-0.5 rounded">
                      {sample.targetedBrand}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">
                    {sample.rawText}
                  </p>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
            <h3 className="text-xs font-semibold uppercase text-slate-400 tracking-wider flex items-center space-x-2">
              <Eye className="w-3.5 h-3.5 text-indigo-400" />
              <span>Why Quishing Bypasses Legacy Filters</span>
            </h3>

            <ul className="text-xs text-slate-400 space-y-2 leading-relaxed">
              <li className="flex items-start space-x-2">
                <span className="text-emerald-400 font-bold">•</span>
                <span><strong>No Text Hyperlink:</strong> Attack vectors hide inside PNG/JPEG raster data, rendering basic textual regex scanners blind.</span>
              </li>
              <li className="flex items-start space-x-2">
                <span className="text-emerald-400 font-bold">•</span>
                <span><strong>Cross-Device Lateral Hop:</strong> Prompts victims to use mobile cameras, bypassing endpoint detection & response (EDR) on corporate laptops.</span>
              </li>
              <li className="flex items-start space-x-2">
                <span className="text-emerald-400 font-bold">•</span>
                <span><strong>Dynamic Shorteners:</strong> Redirect hops unmask final adversary destination only upon live scanning.</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
