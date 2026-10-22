import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Layers, 
  Cpu, 
  ExternalLink, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle, 
  Eye, 
  Zap, 
  Lock, 
  Compass, 
  ArrowRight,
  Sparkles,
  RefreshCw,
  Copy,
  Check
} from 'lucide-react';
import { Link } from 'react-router-dom';

export const ExtensionGuidePage: React.FC = () => {
  const [copiedStep, setCopiedStep] = useState<number | null>(null);
  const [showDemoModal, setShowDemoModal] = useState(false);

  const copyToClipboard = (text: string, stepIndex: number) => {
    navigator.clipboard.writeText(text);
    setCopiedStep(stepIndex);
    setTimeout(() => setCopiedStep(null), 2000);
  };

  const samplePhishUrl = 'http://secure-login-update-paypal-verification.com/account/login';

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-10">
      {/* Hero Section */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-indigo-950/40 border border-slate-800 p-8 sm:p-10 shadow-2xl">
        <div className="absolute top-0 right-0 -mr-16 -mt-16 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 -ml-16 -mb-16 w-80 h-80 bg-red-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
          <div className="space-y-4 max-w-3xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono font-medium">
              <Sparkles className="w-3.5 h-3.5" />
              Endpoint Protection • Chrome Manifest V3 Shield
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              PhishNetra Browser Extension
            </h1>
            <p className="text-base text-slate-300 leading-relaxed">
              The endpoint protection tier of the PhishNetra architecture. Intercepts tab navigation in real time, applies instant client-side heuristics (&lt;5ms), queries the multi-layer AI backend, and injects an un-bypassable DOM interstitial barrier whenever high-confidence phishing indicators are discovered.
            </p>
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                onClick={() => setShowDemoModal(true)}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-medium text-sm transition-all shadow-lg shadow-red-600/30"
              >
                <Eye className="w-4 h-4" />
                Preview Interstitial Warning Overlay
              </button>
              <Link
                to={`/analyze?url=${encodeURIComponent(samplePhishUrl)}`}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-sm border border-slate-700 transition-all"
              >
                <Zap className="w-4 h-4 text-cyan-400" />
                Analyze Sample Threat in Web Console
              </Link>
            </div>
          </div>

          {/* Quick Status Card */}
          <div className="w-full lg:w-80 bg-slate-950/80 backdrop-blur border border-slate-800/80 rounded-xl p-5 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800/60 pb-3">
              <span className="text-slate-400">Extension Engine</span>
              <span className="inline-flex items-center gap-1.5 text-emerald-400 font-semibold">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                Manifest V3
              </span>
            </div>
            <div className="space-y-2 text-slate-300">
              <div className="flex justify-between">
                <span className="text-slate-500">Service Worker:</span>
                <span className="text-slate-200">background.js</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Overlay Isolation:</span>
                <span className="text-slate-200">Shadow DOM / Root</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Mitigation Strategy:</span>
                <span className="text-red-400 font-bold">Zero Silent Redirects</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Backend Endpoint:</span>
                <span className="text-cyan-400">localhost:5000</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Operational Lifecycle Pipeline */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            Zero-Trust Browser Lifecycle & Interception Flow
          </h2>
          <span className="text-xs text-slate-500 font-mono">Real-Time Event Architecture</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3 relative">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold text-sm">
              1
            </div>
            <h3 className="font-semibold text-slate-200 text-sm">Tab Navigation Interception</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Hooked to <code className="text-cyan-300">tabs.onUpdated</code>. Captures requested URL prior to paint. Filters internal schemes and verifies domain against local bypass whitelist.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3 relative">
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400 font-bold text-sm">
              2
            </div>
            <h3 className="font-semibold text-slate-200 text-sm">Client-Side Heuristics</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Sub-millisecond local inspection: Shannon entropy calculation, Punycode/homoglyph tests, IP-literal check, and brand token collision evaluation in the background service worker.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3 relative">
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 font-bold text-sm">
              3
            </div>
            <h3 className="font-semibold text-slate-200 text-sm">Multi-Layer AI Dispatch</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Dispatches URL payload to <code className="text-purple-300">POST /api/analyze</code>. Backend aggregates ML probability, domain age (RDAP), DNS records, TLS certificate, and blacklists.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3 relative">
            <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 font-bold text-sm">
              4
            </div>
            <h3 className="font-semibold text-slate-200 text-sm">DOM Barrier Mitigation</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              If risk score &gt;= 70, content script triggers <code className="text-red-300">showInterstitial()</code>. Freezes host page scrolling and input, displaying threat evidence and analyst choices.
            </p>
          </div>
        </div>
      </div>

      {/* Installation & Developer Setup */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-emerald-400" />
            <h2 className="text-lg font-bold text-white">Load Unpacked Extension in Chrome</h2>
          </div>

          <div className="space-y-4 text-sm">
            <div className="flex items-start gap-3 bg-slate-950/60 border border-slate-800/80 rounded-lg p-3.5">
              <span className="font-mono text-cyan-400 font-bold">1.</span>
              <div className="flex-1 space-y-1">
                <p className="text-slate-300 font-medium">Navigate to Extension Management</p>
                <div className="flex items-center gap-2">
                  <code className="bg-slate-900 px-2 py-0.5 rounded text-xs text-cyan-300 font-mono">
                    chrome://extensions
                  </code>
                  <button
                    onClick={() => copyToClipboard('chrome://extensions', 1)}
                    className="text-slate-500 hover:text-slate-300 transition-colors"
                  >
                    {copiedStep === 1 ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex items-start gap-3 bg-slate-950/60 border border-slate-800/80 rounded-lg p-3.5">
              <span className="font-mono text-cyan-400 font-bold">2.</span>
              <div className="flex-1 space-y-1">
                <p className="text-slate-300 font-medium">Enable Developer Mode</p>
                <p className="text-xs text-slate-400">
                  Toggle the switch located in the upper-right corner of the Extensions page.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3 bg-slate-950/60 border border-slate-800/80 rounded-lg p-3.5">
              <span className="font-mono text-cyan-400 font-bold">3.</span>
              <div className="flex-1 space-y-1">
                <p className="text-slate-300 font-medium">Click "Load unpacked"</p>
                <p className="text-xs text-slate-400">
                  Select the built extension folder:
                </p>
                <div className="flex items-center gap-2 mt-1">
                  <code className="bg-slate-900 px-2 py-1 rounded text-xs text-amber-300 font-mono break-all">
                    apps/extension/dist
                  </code>
                  <button
                    onClick={() => copyToClipboard('apps/extension/dist', 3)}
                    className="text-slate-500 hover:text-slate-300 transition-colors"
                  >
                    {copiedStep === 3 ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex items-start gap-3 bg-slate-950/60 border border-slate-800/80 rounded-lg p-3.5">
              <span className="font-mono text-cyan-400 font-bold">4.</span>
              <div className="flex-1 space-y-1">
                <p className="text-slate-300 font-medium">Verify Active Status</p>
                <p className="text-xs text-slate-400">
                  Pin the PhishNetra icon to your browser toolbar. The shield badge displays real-time verdicts (SAFE, SUSPICIOUS, or PHISHING).
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Security Invariants & Guarantees */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center gap-2">
            <Lock className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-white">Browser Security & Privacy Boundary</h2>
          </div>

          <div className="space-y-3.5 text-sm">
            <div className="flex items-start gap-3">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-slate-200">Zero Credential Harvesting:</strong>
                <p className="text-xs text-slate-400 mt-0.5">
                  Content scripts never access, log, or transmit form input fields, passwords, or authentication cookies.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-slate-200">Minimal Manifest Permissions:</strong>
                <p className="text-xs text-slate-400 mt-0.5">
                  Strictly limited to <code className="text-slate-300 font-mono">activeTab</code>, <code className="text-slate-300 font-mono">storage</code>, and <code className="text-slate-300 font-mono">scripting</code>. Unrelated browsing history is never queried.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-slate-200">Non-Silent Interception:</strong>
                <p className="text-xs text-slate-400 mt-0.5">
                  No automated silent redirects. Users are informed with explicit evidence breakdown, AI confidence, and remediation choices.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-slate-200">Graceful Fail-Safe:</strong>
                <p className="text-xs text-slate-400 mt-0.5">
                  If backend connectivity is lost, client-side local heuristics continue to flag obvious homoglyphs, IP hostnames, and deceptive top-level domains.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Simulated Interstitial Modal Preview */}
      {showDemoModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="relative w-full max-w-2xl bg-gradient-to-b from-slate-900 to-slate-950 border border-red-500/50 rounded-2xl shadow-2xl shadow-red-950/60 p-6 sm:p-8 space-y-6">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400">
                  <ShieldAlert className="w-7 h-7 animate-pulse" />
                </div>
                <div>
                  <span className="text-xs font-mono font-bold tracking-wider text-red-400 uppercase">
                    PHISHNETRA SECURITY BARRIER
                  </span>
                  <h3 className="text-xl font-bold text-white">Deceptive Webpage Intercepted</h3>
                </div>
              </div>
              <button
                onClick={() => setShowDemoModal(false)}
                className="text-slate-400 hover:text-white text-xs font-mono px-2.5 py-1 rounded bg-slate-800 border border-slate-700"
              >
                Close Preview
              </button>
            </div>

            <div className="bg-slate-950 border border-red-500/20 rounded-xl p-4 space-y-2">
              <div className="text-xs text-slate-400 font-mono">SUSPICIOUS DESTINATION</div>
              <div className="font-mono text-sm text-red-300 break-all bg-red-950/30 p-2 rounded border border-red-900/40">
                {samplePhishUrl}
              </div>
              <div className="flex items-center gap-4 pt-1 text-xs">
                <span className="text-slate-400">Composite Risk: <strong className="text-red-400">92 / 100</strong></span>
                <span className="text-slate-400">ML Confidence: <strong className="text-red-400">96.4%</strong></span>
                <span className="text-slate-400">Verdict: <strong className="text-red-400">PHISHING</strong></span>
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-xs font-semibold text-slate-300">CRITICAL THREAT EVIDENCE:</div>
              <ul className="space-y-1.5 text-xs text-slate-300">
                <li className="flex items-center gap-2">
                  <span className="text-red-400 font-bold">✕</span>
                  <span>Brand impersonation detected: Deceptive target targeting <strong>PayPal</strong> credentials</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-red-400 font-bold">✕</span>
                  <span>Domain registered &lt; 48 hours ago (RDAP zero-trust trigger)</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-red-400 font-bold">✕</span>
                  <span>Free Let's Encrypt TLS certificate with abnormal SAN structure</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-red-400 font-bold">✕</span>
                  <span>Subdomain depth &gt; 4 with high Shannon character entropy (4.82)</span>
                </li>
              </ul>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
              <button
                onClick={() => setShowDemoModal(false)}
                className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-colors"
              >
                Return to Safety (Recommended)
              </button>
              <Link
                to={`/analyze?url=${encodeURIComponent(samplePhishUrl)}`}
                onClick={() => setShowDemoModal(false)}
                className="w-full py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs text-center border border-slate-700 transition-colors"
              >
                Inspect Threat Evidence
              </Link>
              <button
                onClick={() => setShowDemoModal(false)}
                className="w-full py-2.5 rounded-lg bg-transparent hover:bg-red-950/40 text-red-400 border border-red-500/30 text-xs font-medium transition-colors"
              >
                Bypass & Proceed (Unsafe)
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
