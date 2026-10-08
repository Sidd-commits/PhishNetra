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

                {/* SOC Ops & SIEM Routes */}
                <Route
                  path="/cases"
                  element={
                    <ProtectedRoute>
                      <CaseManagementPage />
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

                {/* MLOps & AI Lab */}
                <Route
                  path="/mlops"
                  element={
                    <ProtectedRoute>
                      <MLOpsPage />
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

