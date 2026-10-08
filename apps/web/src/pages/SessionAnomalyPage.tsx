import React, { useState } from 'react';
import { api } from '../services/api';
import {
  ContinuousRiskAssessment,
  SessionTelemetryProbe
} from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  Activity,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Globe,
  MapPin,
  Lock,
  RefreshCw,
  Search,
  CheckCircle2,
  XCircle,
  Radio,
  Sliders
} from 'lucide-react';

export const SessionAnomalyPage: React.FC = () => {
  const { showToast } = useToast();
  const [sessionId, setSessionId] = useState('sess-corp-compromised-99');
  const [userEmail, setUserEmail] = useState('victim@enterprise.com');
  const [city, setCity] = useState('Tokyo');
  const [country, setCountry] = useState('Japan');
  const [latitude, setLatitude] = useState(35.6762);
  const [longitude, setLongitude] = useState(139.6503);
  const [ipAddress, setIpAddress] = useState('133.242.18.5');
  const [tlsJa3, setTlsJa3] = useState('771,49195-49199,43-13,29,0');
  const [userAgent, setUserAgent] = useState('python-requests/2.31.0');

  const [evaluating, setEvaluating] = useState(false);
  const [assessment, setAssessment] = useState<ContinuousRiskAssessment | null>(null);

  const handleEvaluate = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setEvaluating(true);
    try {
      const probe: SessionTelemetryProbe = {
        sessionId,
        userEmail,
        timestamp: new Date().toISOString(),
        ipAddress,
        geoCoordinates: { latitude, longitude, city, country },
        tlsJa3Fingerprint: tlsJa3,
        userAgent
      };

      const res = await api.evaluateSessionAnomaly(probe);
      setAssessment(res);
      showToast(
        res.actionTaken === 'TERMINATE_SESSION'
          ? 'threat'
          : res.actionTaken === 'STEP_UP_CHALLENGE'
          ? 'warning'
          : 'success',
        `Session Evaluation: ${res.actionTaken}`,
        `Risk Score: ${res.continuousRiskScore}/100`
      );
    } catch (err: any) {
      showToast('error', 'Evaluation Failed', err.message);
    } finally {
      setEvaluating(false);
    }
  };

  const loadLegitimateScenario = () => {
    setSessionId('sess-legit-user');
    setUserEmail('alice.security@enterprise.com');
    setCity('New York');
    setCountry('United States');
    setLatitude(40.7128);
    setLongitude(-74.006);
    setIpAddress('198.51.100.12');
    setTlsJa3('771,4865-4866-4867,0-23-65281-10-11,29-23-24,0');
    setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120');
    showToast('info', 'Loaded Scenario', 'Legitimate corporate session scenario loaded');
  };

  const loadImpossibleTravelScenario = () => {
    setSessionId('sess-corp-compromised-99');
    setUserEmail('victim@enterprise.com');
    setCity('Tokyo');
    setCountry('Japan');
    setLatitude(35.6762);
    setLongitude(139.6503);
    setIpAddress('133.242.18.5');
    setTlsJa3('771,49195-49199,43-13,29,0'); // Mutated TLS JA3
    setUserAgent('python-requests/2.31.0'); // Mutated UA
    showToast('warning', 'Loaded Scenario', 'Impossible travel attack scenario loaded');
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-amber-950/70 via-slate-900 to-slate-900 border border-amber-500/20 p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
                <Activity className="w-5 h-5" />
              </div>
              <h1 className="text-xl font-bold text-white tracking-wide">
                Zero-Trust Continuous Session Verification
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-full font-semibold">
                Milestone 18
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-400 max-w-2xl leading-relaxed">
              Monitors post-authentication identity validity in real-time. Detects session token theft, impossible travel velocity (&gt;850 km/h), in-flight TLS JA3 fingerprint drift, and autonomous session termination kill switches.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={loadLegitimateScenario}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
            >
              Legitimate Session
            </button>
            <button
              onClick={loadImpossibleTravelScenario}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/30 transition-colors flex items-center space-x-1"
            >
              <Zap className="w-3.5 h-3.5 text-rose-400" />
              <span>Attack Simulation</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Telemetry Probe Form */}
        <div className="space-y-6">
          <form onSubmit={handleEvaluate} className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center space-x-2">
              <Radio className="w-4 h-4 text-amber-400" />
              <span>In-Flight Session Telemetry Probe</span>
            </h2>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Session ID Token</label>
                <input
                  type="text"
                  value={sessionId}
                  onChange={(e) => setSessionId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">User Principal Email</label>
                <input
                  type="email"
                  value={userEmail}
                  onChange={(e) => setUserEmail(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-slate-400 mb-1">Ingress City</label>
                  <input
                    type="text"
                    value={city}
                    onChange={(e) => setCity(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Country</label>
                  <input
                    type="text"
                    value={country}
                    onChange={(e) => setCountry(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-slate-400 mb-1">Latitude</label>
                  <input
                    type="number"
                    step="any"
                    value={latitude}
                    onChange={(e) => setLatitude(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Longitude</label>
                  <input
                    type="number"
                    step="any"
                    value={longitude}
                    onChange={(e) => setLongitude(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Client TLS JA3 Fingerprint</label>
                <input
                  type="text"
                  value={tlsJa3}
                  onChange={(e) => setTlsJa3(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">User-Agent Header</label>
                <input
                  type="text"
                  value={userAgent}
                  onChange={(e) => setUserAgent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono truncate"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={evaluating}
              className="w-full py-2.5 rounded-xl font-semibold bg-amber-500 hover:bg-amber-400 text-slate-950 transition-colors flex items-center justify-center space-x-2 shadow-lg shadow-amber-500/20 text-xs disabled:opacity-50"
            >
              {evaluating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
              <span>Evaluate Continuous Risk</span>
            </button>
          </form>
        </div>

        {/* Right Column: Assessment Outcome Dashboard */}
        <div className="lg:col-span-2 space-y-6">
          {assessment ? (
            <div className="space-y-6 animate-in fade-in duration-300">
              {/* Verdict KPI Card */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                  <div>
                    <span className="text-[10px] font-mono uppercase text-slate-500">Autonomous Defense Decision</span>
                    <div className="flex items-center space-x-2 mt-1">
                      <span
                        className={`px-3 py-1 rounded-xl text-xs font-bold uppercase tracking-wider flex items-center space-x-1.5 ${
                          assessment.actionTaken === 'TERMINATE_SESSION'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : assessment.actionTaken === 'STEP_UP_CHALLENGE'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        }`}
                      >
                        {assessment.actionTaken === 'TERMINATE_SESSION' ? (
                          <XCircle className="w-3.5 h-3.5 text-rose-400" />
                        ) : assessment.actionTaken === 'STEP_UP_CHALLENGE' ? (
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        ) : (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        )}
                        <span>{assessment.actionTaken}</span>
                      </span>

                      {assessment.killSwitchDispatched && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                          Kill Switch Emitted
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="text-[10px] font-mono text-slate-500">Continuous Risk Score</span>
                    <div className={`text-2xl font-bold font-mono ${
                      assessment.continuousRiskScore >= 75
                        ? 'text-rose-400'
                        : assessment.continuousRiskScore >= 45
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }`}>
                      {assessment.continuousRiskScore} / 100
                    </div>
                  </div>
                </div>

                {/* Anomalies Detected */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
                    Anomalies & Behavioral Signals
                  </span>
                  {assessment.anomaliesDetected.length > 0 ? (
                    assessment.anomaliesDetected.map((anom, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-xl bg-slate-950/70 border border-rose-500/30 text-xs text-rose-300 flex items-start space-x-2"
                      >
                        <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                        <span>{anom}</span>
                      </div>
                    ))
                  ) : (
                    <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs text-slate-400">
                      Zero anomalies detected. Session velocity, device profile, and TLS signatures match legitimate session baseline.
                    </div>
                  )}
                </div>

                {/* Anomaly Metrics Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs">
                  <div className="p-3 rounded-xl bg-slate-950/50 border border-slate-800/80 space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Travel Velocity</span>
                    <div className="text-sm font-bold font-mono text-white">
                      {assessment.impossibleTravelVelocityKmh !== undefined ? `${assessment.impossibleTravelVelocityKmh.toLocaleString()} km/h` : 'N/A (First Probe)'}
                    </div>
                    <span className="text-[10px] text-slate-400">Threshold: 850 km/h</span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950/50 border border-slate-800/80 space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">TLS JA3 Drift</span>
                    <div className={`text-sm font-bold font-mono ${assessment.tlsDriftDetected ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {assessment.tlsDriftDetected ? 'DRIFT DETECTED' : 'CONSISTENT'}
                    </div>
                    <span className="text-[10px] text-slate-400">Transport fingerprint check</span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950/50 border border-slate-800/80 space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Device Profile</span>
                    <div className={`text-sm font-bold font-mono ${assessment.deviceProfileMutated ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {assessment.deviceProfileMutated ? 'MUTATED' : 'STABLE'}
                    </div>
                    <span className="text-[10px] text-slate-400">Browser / OS agent signature</span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-10 shadow-lg text-center space-y-3">
              <Activity className="w-10 h-10 text-slate-600 mx-auto" />
              <h3 className="text-sm font-semibold text-slate-300">Continuous Verification Idle</h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Submit an in-flight session probe or select a scenario above to calculate the dynamic Continuous Risk Score and trigger automated session revocation kill switches.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
