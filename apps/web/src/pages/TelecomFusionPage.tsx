import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import {
  TelecomThreatProbe,
  TelecomThreatAssessment
} from '@phishnetra/shared';
import {
  PhoneCall,
  MessageSquareWarning,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Flame,
  AlertTriangle,
  History,
  Activity,
  Layers
} from 'lucide-react';

export const TelecomFusionPage: React.FC = () => {
  const { showToast } = useToast();
  const [channel, setChannel] = useState<TelecomThreatProbe['channel']>('SMS_SMISHING');
  const [callerOrSenderId, setCallerOrSenderId] = useState<string>('CHASE-ALERT');
  const [stirShakenAttestation, setStirShakenAttestation] = useState<TelecomThreatProbe['stirShakenAttestation']>('UNATTESTED');
  const [messageOrTranscript, setMessageOrTranscript] = useState<string>(
    'Urgent Security Alert: Your Chase debit card has been suspended due to an unauthorized transaction of $489.20. Verify your identity immediately at https://chase-auth-login.top/verify or press 1 to connect with a fraud specialist.'
  );
  const [extractedUrlsStr, setExtractedUrlsStr] = useState<string>('https://chase-auth-login.top/verify');
  const [loading, setLoading] = useState<boolean>(false);
  const [currentAssessment, setCurrentAssessment] = useState<TelecomThreatAssessment | null>(null);
  const [history, setHistory] = useState<TelecomThreatAssessment[]>([]);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const data = await api.getTelecomThreatHistory();
      setHistory(data);
    } catch {
      // Non-critical background fetch
    }
  };

  const handleAssess = async () => {
    if (!callerOrSenderId.trim()) {
      showToast('warning', 'Missing Sender ID', 'Please specify a phone number or sender identifier.');
      return;
    }

    setLoading(true);
    try {
      const urls = extractedUrlsStr
        .split(',')
        .map(u => u.trim())
        .filter(u => u.length > 0);

      const assessment = await api.assessTelecomThreat({
        channel,
        callerOrSenderId,
        messageOrTranscript,
        stirShakenAttestation,
        extractedUrls: urls
      });

      setCurrentAssessment(assessment);
      if (assessment.verdict === 'CRITICAL_CONVERGENCE') {
        showToast('threat', 'Critical Multi-Vector Convergence!', `MVCI Score: ${assessment.multiVectorConvergenceIndex}/100`);
      } else {
        showToast('info', 'Assessment Complete', `Verdict: ${assessment.verdict}`);
      }
      fetchHistory();
    } catch (err: any) {
      showToast('error', 'Assessment Error', err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const loadSmishingPreset = () => {
    setChannel('SMS_SMISHING');
    setCallerOrSenderId('AMAZON-FRAUD');
    setStirShakenAttestation('UNATTESTED');
    setMessageOrTranscript('Your Amazon order #849-29184 has been put on hold. Immediate verification required: https://amzn-security-billing.biz');
    setExtractedUrlsStr('https://amzn-security-billing.biz');
  };

  const loadVishingPreset = () => {
    setChannel('VOIP_VISHING');
    setCallerOrSenderId('+18005550199');
    setStirShakenAttestation('C');
    setMessageOrTranscript('This is an automated message from the Department of Homeland Security. Do not hang up. Your social security number has been compromised. Press 1 immediately to speak with a federal agent.');
    setExtractedUrlsStr('');
  };

  const loadLegitimatePreset = () => {
    setChannel('VOIP_VISHING');
    setCallerOrSenderId('+14155552671');
    setStirShakenAttestation('A');
    setMessageOrTranscript('Good morning, this is Dr. Sarah from Bay Area Health confirming your routine physical exam scheduled for tomorrow at 2:30 PM.');
    setExtractedUrlsStr('');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 lg:p-8 font-sans">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-xl bg-orange-500/10 border border-orange-500/30 text-orange-400">
                <Radio className="w-5 h-5" />
              </div>
              <h1 className="text-xl font-bold text-white tracking-wide">
                Telecom Multi-Vector Threat Fusion
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase bg-orange-500/20 text-orange-300 border border-orange-500/30 rounded-full font-semibold">
                Milestone 19
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-400 max-w-2xl leading-relaxed">
              Correlates SMS smishing, VoIP deepfake vishing, and FCC STIR/SHAKEN caller verification. Calculates Multi-Vector Convergence Index (MVCI) when adversaries link telecom lures with web infrastructure.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={loadSmishingPreset}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/30 transition-colors flex items-center space-x-1"
            >
              <MessageSquareWarning className="w-3.5 h-3.5" />
              <span>Smishing Link</span>
            </button>
            <button
              onClick={loadVishingPreset}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 transition-colors flex items-center space-x-1"
            >
              <PhoneCall className="w-3.5 h-3.5" />
              <span>Vishing Robocall</span>
            </button>
            <button
              onClick={loadLegitimatePreset}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
            >
              Verified Caller
            </button>
          </div>
        </div>

        {/* Input & Assessment Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-4">
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4">
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                <Activity className="w-4 h-4 text-orange-400" />
                <span>Telecom Probe Telemetry Parameters</span>
              </span>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                    Channel Vector
                  </label>
                  <select
                    value={channel}
                    onChange={e => setChannel(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-orange-500"
                  >
                    <option value="SMS_SMISHING">SMS Smishing</option>
                    <option value="VOIP_VISHING">VoIP Vishing</option>
                    <option value="MMS">MMS Multi-Media</option>
                    <option value="CROSS_CHANNEL">Cross-Channel Hybrid</option>
                  </select>
                </div>

                <div>
                  <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                    Caller / Sender ID
                  </label>
                  <input
                    type="text"
                    value={callerOrSenderId}
                    onChange={e => setCallerOrSenderId(e.target.value)}
                    placeholder="e.g. +14155550199 or CHASE-ALERT"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-orange-500"
                  />
                </div>

                <div>
                  <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                    STIR/SHAKEN Attestation
                  </label>
                  <select
                    value={stirShakenAttestation}
                    onChange={e => setStirShakenAttestation(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-orange-500"
                  >
                    <option value="A">Level A (Full Attestation - Verified)</option>
                    <option value="B">Level B (Partial - Customer Only)</option>
                    <option value="C">Level C (Gateway Transit Only)</option>
                    <option value="UNATTESTED">UNATTESTED (Spoofing Risk)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  Message Body / Voice Audio Transcript
                </label>
                <textarea
                  value={messageOrTranscript}
                  onChange={e => setMessageOrTranscript(e.target.value)}
                  rows={4}
                  placeholder="Transcript of call audio or raw SMS text content..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-orange-500 transition-colors resize-none leading-relaxed"
                />
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                  Extracted Web URLs (Comma-separated)
                </label>
                <input
                  type="text"
                  value={extractedUrlsStr}
                  onChange={e => setExtractedUrlsStr(e.target.value)}
                  placeholder="https://suspect-link.com/auth"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-orange-500"
                />
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={handleAssess}
                  disabled={loading}
                  className="px-5 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-orange-500 to-amber-600 hover:from-orange-400 hover:to-amber-500 text-white shadow-lg shadow-orange-500/20 transition-all flex items-center space-x-2 disabled:opacity-50"
                >
                  <Flame className="w-3.5 h-3.5" />
                  <span>{loading ? 'Evaluating Fusion...' : 'Run Telecom Fusion Assessment'}</span>
                </button>
              </div>
            </div>

            {/* Assessment History Table */}
            {history.length > 0 && (
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-3">
                <div className="flex items-center space-x-2 text-xs font-bold text-slate-200 uppercase tracking-wider">
                  <History className="w-4 h-4 text-orange-400" />
                  <span>Recent Telecom Assessments ({history.length})</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="text-[10px] uppercase text-slate-500 border-b border-slate-800">
                      <tr>
                        <th className="py-2 px-3">Sender / Caller</th>
                        <th className="py-2 px-3">Channel</th>
                        <th className="py-2 px-3">STIR/SHAKEN</th>
                        <th className="py-2 px-3">MVCI</th>
                        <th className="py-2 px-3">Verdict</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {history.slice(0, 5).map((item, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-2 px-3 font-semibold text-white">{item.callerOrSenderId}</td>
                          <td className="py-2 px-3 text-slate-400">{item.channel}</td>
                          <td className="py-2 px-3">{item.stirShakenAttestation}</td>
                          <td className="py-2 px-3 text-orange-400 font-bold">{item.multiVectorConvergenceIndex}</td>
                          <td className="py-2 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                item.verdict === 'CRITICAL_CONVERGENCE'
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                  : item.verdict === 'SUSPICIOUS'
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              }`}
                            >
                              {item.verdict}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* Verdict Card */}
          <div className="space-y-4">
            {currentAssessment ? (
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-5 animate-in fade-in">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                    Convergence Verdict
                  </span>
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono ${
                      currentAssessment.verdict === 'CRITICAL_CONVERGENCE'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        : currentAssessment.verdict === 'SUSPICIOUS'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    }`}
                  >
                    {currentAssessment.verdict}
                  </span>
                </div>

                {/* MVCI Score Display */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">Multi-Vector Convergence Index (MVCI)</span>
                    <span className="font-mono text-lg font-bold text-orange-400">
                      {currentAssessment.multiVectorConvergenceIndex} / 100
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all duration-500 ${
                        currentAssessment.multiVectorConvergenceIndex >= 70
                          ? 'bg-rose-500'
                          : currentAssessment.multiVectorConvergenceIndex >= 40
                          ? 'bg-amber-500'
                          : 'bg-emerald-500'
                      }`}
                      style={{ width: `${currentAssessment.multiVectorConvergenceIndex}%` }}
                    />
                  </div>

                  <div className="pt-2 space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Action</span>
                      <span className="font-mono font-bold text-slate-200">
                        {currentAssessment.recommendedTelecomAction}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Synthetic Voice Likelihood</span>
                      <span className="font-mono text-purple-400 font-bold">
                        {currentAssessment.syntheticVoiceLikelihood}%
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Social Engineering Urgency</span>
                      <span className="font-mono text-rose-400 font-bold">
                        {currentAssessment.urgencySocialEngineeringScore}%
                      </span>
                    </div>
                    {currentAssessment.correlatedCampaignId && (
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Correlated Campaign</span>
                        <span className="font-mono text-cyan-400 text-[11px]">
                          {currentAssessment.correlatedCampaignId}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Anomalies Detected */}
                <div className="space-y-2">
                  <span className="text-[10px] font-mono uppercase text-slate-400">
                    Flagged Anomalies ({currentAssessment.anomaliesDetected.length})
                  </span>
                  {currentAssessment.anomaliesDetected.length > 0 ? (
                    <div className="space-y-1.5">
                      {currentAssessment.anomaliesDetected.map((anomaly, idx) => (
                        <div
                          key={idx}
                          className="flex items-start space-x-2 text-xs p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 font-mono"
                        >
                          <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                          <span>{anomaly}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs flex items-center space-x-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      <span>Legitimate telecom signature with Full Attestation A.</span>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-slate-900/40 border border-slate-800/60 rounded-2xl p-6 text-center text-slate-500 space-y-2">
                <Radio className="w-8 h-8 mx-auto opacity-30 text-orange-400" />
                <p className="text-xs">
                  Run an assessment to fuse smishing and deepfake vishing signals into the Multi-Vector Convergence Index.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
