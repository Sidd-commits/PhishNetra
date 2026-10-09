import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Navbar } from './components/Navbar';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { DashboardPage } from './pages/DashboardPage';
import { AnalyzePage } from './pages/AnalyzePage';
import { AnalysisDetailPage } from './pages/AnalysisDetailPage';
import { BatchPage } from './pages/BatchPage';
import { DomainDossierPage } from './pages/DomainDossierPage';
import { ReportsPage } from './pages/ReportsPage';
import { ThreatGraphPage } from './pages/ThreatGraphPage';
import { CampaignsPage } from './pages/CampaignsPage';
import { MLOpsPage } from './pages/MLOpsPage';
import { SIEMIntegrationPage } from './pages/SIEMIntegrationPage';
import { CaseManagementPage } from './pages/CaseManagementPage';
import { EmailIngestionPage } from './pages/EmailIngestionPage';
import { SettingsPage } from './pages/SettingsPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { FeedSyncPage } from './pages/FeedSyncPage';
import { SimulationPage } from './pages/SimulationPage';
import { TakedownCenterPage } from './pages/TakedownCenterPage';
import { OrganizationPage } from './pages/OrganizationPage';
import { ExecutiveBriefingPage } from './pages/ExecutiveBriefingPage';
import { PlaybooksPage } from './pages/PlaybooksPage';
import { ThreatHuntingPage } from './pages/ThreatHuntingPage';
import { ThreatCopilotPage } from './pages/ThreatCopilotPage';
import { CanaryDeceptionPage } from './pages/CanaryDeceptionPage';
import { AttackSurfacePage } from './pages/AttackSurfacePage';
import { RBISandboxPage } from './pages/RBISandboxPage';
import { PhishingTarpitPage } from './pages/PhishingTarpitPage';
import { AiTMDefensePage } from './pages/AiTMDefensePage';
import { ThreatFusionPage } from './pages/ThreatFusionPage';
import { QuishingDefensePage } from './pages/QuishingDefensePage';
import { ThreatAttributionPage } from './pages/ThreatAttributionPage';
import { ClientDefensePage } from './pages/ClientDefensePage';
import { SessionAnomalyPage } from './pages/SessionAnomalyPage';
import { D3FENDMatrixPage } from './pages/D3FENDMatrixPage';
import { GenAIDefensePage } from './pages/GenAIDefensePage';
import { TelecomFusionPage } from './pages/TelecomFusionPage';
import { DigitalForensicsPage } from './pages/DigitalForensicsPage';
import { CTIExchangePage } from './pages/CTIExchangePage';
import { BGPIntegrityPage } from './pages/BGPIntegrityPage';
import { FIDO2GuardPage } from './pages/FIDO2GuardPage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500/20 selection:text-cyan-300">
            <Navbar />
            <main className="flex-1">
              <Routes>
                {/* Public Routes */}
                <Route path="/login" element={<LoginPage />} />
                <Route path="/register" element={<RegisterPage />} />

                {/* Protected Detection Routes */}
                <Route
                  path="/dashboard"
                  element={
                    <ProtectedRoute>
                      <DashboardPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/analyze"
                  element={
                    <ProtectedRoute>
                      <AnalyzePage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/analysis/:id"
                  element={
                    <ProtectedRoute>
                      <AnalysisDetailPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/batch"
                  element={
                    <ProtectedRoute>
                      <BatchPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/email-scanner"
                  element={
                    <ProtectedRoute>
                      <EmailIngestionPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/domains"
                  element={
                    <ProtectedRoute>
                      <DomainDossierPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/domains/:domain"
                  element={
                    <ProtectedRoute>
                      <DomainDossierPage />
                    </ProtectedRoute>
                  }
                />

                {/* Threat Intel Routes */}
                <Route
                  path="/graph"
                  element={
                    <ProtectedRoute>
                      <ThreatGraphPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/threat-graph"
                  element={
                    <ProtectedRoute>
                      <ThreatGraphPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/campaigns"
                  element={
                    <ProtectedRoute>
                      <CampaignsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/feeds"
                  element={
                    <ProtectedRoute>
                      <FeedSyncPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/reports"
                  element={
                    <ProtectedRoute>
                      <ReportsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/executive-briefing"
                  element={
                    <ProtectedRoute>
                      <ExecutiveBriefingPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/hunting"
                  element={
                    <ProtectedRoute>
                      <ThreatHuntingPage />
                    </ProtectedRoute>
                  }
                />

                {/* SOC Ops & SIEM Routes */}
                <Route
                  path="/playbooks"
                  element={
                    <ProtectedRoute>
                      <PlaybooksPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/cases"
                  element={
                    <ProtectedRoute>
                      <CaseManagementPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/takedowns"
                  element={
                    <ProtectedRoute>
                      <TakedownCenterPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/siem"
                  element={
                    <ProtectedRoute>
                      <SIEMIntegrationPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/integrations"
                  element={
                    <ProtectedRoute>
                      <SIEMIntegrationPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/audit-logs"
                  element={
                    <ProtectedRoute>
                      <AuditLogsPage />
                    </ProtectedRoute>
                  }
                />

                {/* Organization & Team Workspace */}
                <Route
                  path="/organization"
                  element={
                    <ProtectedRoute>
                      <OrganizationPage />
                    </ProtectedRoute>
                  }
                />

                {/* MLOps & AI Lab */}
                <Route
                  path="/mlops"
                  element={
                    <ProtectedRoute>
                      <MLOpsPage />
                    </ProtectedRoute>
                  }
                />

                {/* Threat Simulation Lab & Red Team Sandbox */}
                <Route
                  path="/simulation"
                  element={
                    <ProtectedRoute>
                      <SimulationPage />
                    </ProtectedRoute>
                  }
                />

                {/* AI SOC Co-Pilot Assistant */}
                <Route
                  path="/copilot"
                  element={
                    <ProtectedRoute>
                      <ThreatCopilotPage />
                    </ProtectedRoute>
                  }
                />

                {/* Canary Deception Engine */}
                <Route
                  path="/deception"
                  element={
                    <ProtectedRoute>
                      <CanaryDeceptionPage />
                    </ProtectedRoute>
                  }
                />

                {/* External Attack Surface Management */}
                <Route
                  path="/attack-surface"
                  element={
                    <ProtectedRoute>
                      <AttackSurfacePage />
                    </ProtectedRoute>
                  }
                />

                {/* Zero-Trust Remote Browser Isolation (RBI) Sandbox */}
                <Route
                  path="/rbi-sandbox"
                  element={
                    <ProtectedRoute>
                      <RBISandboxPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/rbi"
                  element={
                    <ProtectedRoute>
                      <RBISandboxPage />
                    </ProtectedRoute>
                  }
                />

                {/* Phishing Tarpit & Credential Poisoner */}
                <Route
                  path="/tarpit"
                  element={
                    <ProtectedRoute>
                      <PhishingTarpitPage />
                    </ProtectedRoute>
                  }
                />

                {/* Adversary-in-the-Middle (AiTM) Reverse Proxy Defense */}
                <Route
                  path="/aitm-defense"
                  element={
                    <ProtectedRoute>
                      <AiTMDefensePage />
                    </ProtectedRoute>
                  }
                />

                {/* Threat Intelligence Fusion & Compliance Studio */}
                <Route
                  path="/intel-fusion"
                  element={
                    <ProtectedRoute>
                      <ThreatFusionPage />
                    </ProtectedRoute>
                  }
                />

                {/* Multimodal Quishing (QR Code) Defense */}
                <Route
                  path="/quishing"
                  element={
                    <ProtectedRoute>
                      <QuishingDefensePage />
                    </ProtectedRoute>
                  }
                />

                {/* Threat Actor Attribution & FAIR Cyber Risk Studio */}
                <Route
                  path="/threat-attribution"
                  element={
                    <ProtectedRoute>
                      <ThreatAttributionPage />
                    </ProtectedRoute>
                  }
                />

                {/* Client-Side Anti-Tampering & DOM Cloaking Defense SDK */}
                <Route
                  path="/client-defense"
                  element={
                    <ProtectedRoute>
                      <ClientDefensePage />
                    </ProtectedRoute>
                  }
                />

                {/* Zero-Trust Continuous Session Verification */}
                <Route
                  path="/session-anomaly"
                  element={
                    <ProtectedRoute>
                      <SessionAnomalyPage />
                    </ProtectedRoute>
                  }
                />

                {/* MITRE D3FEND Defensive Matrix Mapping */}
                <Route
                  path="/d3fend"
                  element={
                    <ProtectedRoute>
                      <D3FENDMatrixPage />
                    </ProtectedRoute>
                  }
                />

                {/* GenAI Adversarial & Prompt Injection Defense */}
                <Route
                  path="/genai-defense"
                  element={
                    <ProtectedRoute>
                      <GenAIDefensePage />
                    </ProtectedRoute>
                  }
                />

                {/* Telecom Multi-Vector Threat Fusion */}
                <Route
                  path="/telecom-threat"
                  element={
                    <ProtectedRoute>
                      <TelecomFusionPage />
                    </ProtectedRoute>
                  }
                />

                {/* Automated Digital Forensics & HAR Packet Inspection */}
                <Route
                  path="/digital-forensics"
                  element={
                    <ProtectedRoute>
                      <DigitalForensicsPage />
                    </ProtectedRoute>
                  }
                />

                {/* Milestone 20: Decentralized CTI TAXII Exchange */}
                <Route
                  path="/cti-exchange"
                  element={
                    <ProtectedRoute>
                      <CTIExchangePage />
                    </ProtectedRoute>
                  }
                />

                {/* Milestone 20: BGP Route & DNS Poisoning Radar */}
                <Route
                  path="/bgp-integrity"
                  element={
                    <ProtectedRoute>
                      <BGPIntegrityPage />
                    </ProtectedRoute>
                  }
                />

                {/* Milestone 20: FIDO2 / WebAuthn MFA Credential Guard */}
                <Route
                  path="/fido2-guard"
                  element={
                    <ProtectedRoute>
                      <FIDO2GuardPage />
                    </ProtectedRoute>
                  }
                />

                {/* Policy & Calibration Settings */}
                <Route
                  path="/settings"
                  element={
                    <ProtectedRoute>
                      <SettingsPage />
                    </ProtectedRoute>
                  }
                />

                {/* Fallback */}
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
              </Routes>
            </main>

            {/* Footer */}
            <footer className="border-t border-slate-900 bg-slate-950/90 py-6 text-center text-xs text-slate-500 font-mono">
              <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
                <div>
                  PhishNetra Cybersecurity Platform • Enterprise Governance & Live Threat Mitigation
                </div>
                <div className="text-slate-600">
                  Zero-Trust Real-Time Threat Mitigation & Autonomous Incident Response
                </div>
              </div>
            </footer>
          </div>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;

