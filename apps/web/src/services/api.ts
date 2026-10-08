import axios, { AxiosInstance } from 'axios';
import {
  AuthResponse,
  LoginRequest,
  RegisterRequest,
  AnalysisResponse,
  AnalysisSummary,
  UserProfile,
  BatchJobRequest,
  BatchJobResponse,
  DomainDossier,
  TyposquattingScanResult,
  CreateReportRequest,
  ReportModerationRequest,
  CommunityReport,
  QueueMetrics,
  CacheStats,
  SHAPExplanation,
  ModelRegistryOverview,
  ModelMetadata,
  DriftReport,
  AdversarialEvaluationReport,
  SIEMExportRequest,
  SIEMExportResult,
  WebhookConfig,
  CreateWebhookRequest,
  WebhookDeliveryLog,
  SOCCase,
  CreateCaseRequest,
  UpdateCaseRequest,
  RemediationType,
  RemediationResult,
  EmailAnalysisRequest,
  EmailAnalysisResult,
  RawIOCExtractionResult,
  SystemConfig,
  UpdateSystemConfigRequest,
  ApiKeyItem,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  AuditLogEntry,
  ThreatFeedStatus,
  ThreatFeedSyncResult,
  AttackScenarioPreset,
  AttackSimulationRequest,
  AttackSimulationResult,
  DefenseBenchmarkReport,
  TakedownNotice,
  CreateTakedownRequest,
  OrganizationWorkspace,
  TeamMember,
  OrganizationRole,
  ExecutiveThreatReport
} from '@phishnetra/shared';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

class ApiService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Request interceptor to automatically attach JWT from localStorage if present
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('phishnetra_token');
        if (token && config.headers) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );
  }

  // --- Authentication ---
  public async register(data: RegisterRequest): Promise<AuthResponse> {
    const res = await this.client.post<AuthResponse>('/auth/register', data);
    return res.data;
  }

  public async login(data: LoginRequest): Promise<AuthResponse> {
    const res = await this.client.post<AuthResponse>('/auth/login', data);
    return res.data;
  }

  public async logout(): Promise<void> {
    await this.client.post('/auth/logout');
  }

  public async getMe(): Promise<{ user: UserProfile }> {
    const res = await this.client.get<{ user: UserProfile }>('/auth/me');
    return res.data;
  }

  // --- Threat Analysis ---
  public async analyzeUrl(url: string, analyzePage: boolean = true): Promise<AnalysisResponse> {
    const res = await this.client.post<AnalysisResponse>('/analyze', { url, analyzePage });
    return res.data;
  }

  public async getHistory(limit: number = 20, offset: number = 0): Promise<{ items: AnalysisSummary[]; total: number }> {
    const res = await this.client.get<{ items: AnalysisSummary[]; total: number }>(`/analyze/history?limit=${limit}&offset=${offset}`);
    return res.data;
  }

  public async getAnalysisById(id: string): Promise<AnalysisResponse> {
    const res = await this.client.get<AnalysisResponse>(`/analyze/${id}`);
    return res.data;
  }

  // --- Milestone 4: Async Batch Analysis ---
  public async createBatchJob(data: BatchJobRequest): Promise<BatchJobResponse> {
    const res = await this.client.post<BatchJobResponse>('/batch', data);
    return res.data;
  }

  public async getBatchJob(id: string): Promise<BatchJobResponse> {
    const res = await this.client.get<BatchJobResponse>(`/batch/${id}`);
    return res.data;
  }

  public async listBatchJobs(limit: number = 20, offset: number = 0): Promise<{ total: number; limit: number; offset: number; jobs: BatchJobResponse[] }> {
    const res = await this.client.get<{ total: number; limit: number; offset: number; jobs: BatchJobResponse[] }>(`/batch?limit=${limit}&offset=${offset}`);
    return res.data;
  }

  public async cancelBatchJob(id: string): Promise<{ success: boolean; message: string }> {
    const res = await this.client.post<{ success: boolean; message: string }>(`/batch/${id}/cancel`);
    return res.data;
  }

  public getBatchExportUrl(id: string, format: 'csv' | 'json' = 'csv'): string {
    return `${API_BASE_URL}/batch/${id}/export?format=${format}`;
  }

  // --- Milestone 4: Domain Dossier & Typosquatting ---
  public async getDomainDossier(domain: string): Promise<DomainDossier> {
    const res = await this.client.get<DomainDossier>(`/domains/${encodeURIComponent(domain)}`);
    return res.data;
  }

  public async scanTyposquatting(domain: string): Promise<TyposquattingScanResult> {
    const res = await this.client.post<TyposquattingScanResult>('/domains/typosquatting', { domain });
    return res.data;
  }

  // --- Milestone 4: Community Threat Reports ---
  public async createReport(data: CreateReportRequest): Promise<CommunityReport> {
    const res = await this.client.post<CommunityReport>('/reports', data);
    return res.data;
  }

  public async listReports(filters?: {
    status?: string;
    reportType?: string;
    domain?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ total: number; limit: number; offset: number; reports: CommunityReport[] }> {
    const params = new URLSearchParams();
    if (filters?.status) params.append('status', filters.status);
    if (filters?.reportType) params.append('reportType', filters.reportType);
    if (filters?.domain) params.append('domain', filters.domain);
    if (filters?.limit) params.append('limit', String(filters.limit));
    if (filters?.offset) params.append('offset', String(filters.offset));

    const res = await this.client.get<{ total: number; limit: number; offset: number; reports: CommunityReport[] }>(`/reports?${params.toString()}`);
    return res.data;
  }

  public async getReportById(id: string): Promise<CommunityReport> {
    const res = await this.client.get<CommunityReport>(`/reports/${id}`);
    return res.data;
  }

  public async moderateReport(id: string, data: ReportModerationRequest): Promise<CommunityReport> {
    const res = await this.client.patch<CommunityReport>(`/reports/${id}/moderate`, data);
    return res.data;
  }

  // --- Milestone 4: System Telemetry & Metrics ---
  public async getSystemMetrics(): Promise<{ queue: QueueMetrics; cache: CacheStats; timestamp: string }> {
    const res = await this.client.get<{ queue: QueueMetrics; cache: CacheStats; timestamp: string }>('/system/metrics');
    return res.data;
  }

  // --- Milestone 7: MLOps, SHAP & Retraining Lifecycle ---
  public async explainPrediction(url: string): Promise<SHAPExplanation> {
    const res = await this.client.post<{ success: boolean; data: SHAPExplanation }>('/mlops/explain', { url });
    return res.data.data;
  }

  public async getModelRegistry(): Promise<ModelRegistryOverview> {
    const res = await this.client.get<{ success: boolean; data: ModelRegistryOverview }>('/mlops/models');
    return res.data.data;
  }

  public async activateModel(version: string): Promise<any> {
    const res = await this.client.post('/mlops/models/activate', { version });
    return res.data;
  }

  public async getDriftMetrics(liveUrls?: string[]): Promise<DriftReport> {
    if (liveUrls && liveUrls.length > 0) {
      const res = await this.client.post<{ success: boolean; data: DriftReport }>('/mlops/drift/evaluate', { live_urls: liveUrls });
      return res.data.data;
    }
    const res = await this.client.get<{ success: boolean; data: DriftReport }>('/mlops/drift');
    return res.data.data;
  }

  public async triggerRetraining(params: {
    dataset_path?: string;
    augmented_samples?: Array<{ url: string; label: number }>;
    algorithm?: string;
    auto_activate_threshold?: number;
    version_tag?: string;
  }): Promise<any> {
    const res = await this.client.post('/mlops/retrain', params);
    return res.data;
  }

  public async runAdversarialTest(params: {
    url?: string;
    attack_types?: string[];
    custom_urls?: string[];
  }): Promise<AdversarialEvaluationReport> {
    const res = await this.client.post<{ success: boolean; data: AdversarialEvaluationReport }>('/mlops/adversarial', params);
    return res.data.data;
  }

  // --- Milestone 8: SIEM / SOAR Multi-Format Exporter ---
  public async exportSIEM(req: SIEMExportRequest): Promise<SIEMExportResult> {
    const res = await this.client.post<{ success: boolean; data: SIEMExportResult }>('/siem/export', req);
    return res.data.data;
  }

  // --- Milestone 8: Webhook & Alert Notifications ---
  public async listWebhooks(): Promise<WebhookConfig[]> {
    const res = await this.client.get<{ success: boolean; data: WebhookConfig[] }>('/notifications/webhooks');
    return res.data.data;
  }

  public async createWebhook(req: CreateWebhookRequest): Promise<WebhookConfig> {
    const res = await this.client.post<{ success: boolean; data: WebhookConfig }>('/notifications/webhooks', req);
    return res.data.data;
  }

  public async deleteWebhook(id: string): Promise<boolean> {
    const res = await this.client.delete<{ success: boolean }>(`/notifications/webhooks/${id}`);
    return res.data.success;
  }

  public async testWebhook(id: string): Promise<WebhookDeliveryLog> {
    const res = await this.client.post<{ success: boolean; data: WebhookDeliveryLog }>(`/notifications/webhooks/${id}/test`);
    return res.data.data;
  }

  public async getWebhookLogs(limit?: number): Promise<WebhookDeliveryLog[]> {
    const res = await this.client.get<{ success: boolean; data: WebhookDeliveryLog[] }>(`/notifications/logs${limit ? `?limit=${limit}` : ''}`);
    return res.data.data;
  }

  // --- Milestone 8: SOC Case Management & Remediation ---
  public async listCases(filters?: { status?: string; severity?: string }): Promise<SOCCase[]> {
    const params = new URLSearchParams();
    if (filters?.status) params.append('status', filters.status);
    if (filters?.severity) params.append('severity', filters.severity);
    const res = await this.client.get<{ success: boolean; data: SOCCase[] }>(`/cases?${params.toString()}`);
    return res.data.data;
  }

  public async getCase(id: string): Promise<SOCCase> {
    const res = await this.client.get<{ success: boolean; data: SOCCase }>(`/cases/${id}`);
    return res.data.data;
  }

  public async createCase(req: CreateCaseRequest): Promise<SOCCase> {
    const res = await this.client.post<{ success: boolean; data: SOCCase }>('/cases', req);
    return res.data.data;
  }

  public async updateCase(id: string, req: UpdateCaseRequest): Promise<SOCCase> {
    const res = await this.client.patch<{ success: boolean; data: SOCCase }>(`/cases/${id}`, req);
    return res.data.data;
  }

  public async addCaseNote(id: string, data: { author: string; text: string }): Promise<SOCCase> {
    const res = await this.client.post<{ success: boolean; data: SOCCase }>(`/cases/${id}/notes`, data);
    return res.data.data;
  }

  public async remediateCase(id: string, actionType: RemediationType): Promise<RemediationResult> {
    const res = await this.client.post<{ success: boolean; data: RemediationResult }>(`/cases/${id}/remediate`, { actionType });
    return res.data.data;
  }

  // --- Milestone 8: Email & Raw IOC Ingestion ---
  public async analyzeEmail(req: EmailAnalysisRequest): Promise<EmailAnalysisResult> {
    const res = await this.client.post<{ success: boolean; data: EmailAnalysisResult }>('/ingest/email', req);
    return res.data.data;
  }

  public async extractRawIOCs(rawText: string): Promise<RawIOCExtractionResult> {
    const res = await this.client.post<{ success: boolean; data: RawIOCExtractionResult }>('/ingest/raw-ioc', { rawText });
    return res.data.data;
  }

  // --- Milestone 9: Governance, Calibration, Audit & Feeds ---
  public async getSystemConfig(): Promise<SystemConfig> {
    const res = await this.client.get<{ success: boolean; data: SystemConfig }>('/settings/config');
    return res.data.data;
  }

  public async updateSystemConfig(req: UpdateSystemConfigRequest): Promise<SystemConfig> {
    const res = await this.client.patch<{ success: boolean; data: SystemConfig }>('/settings/config', req);
    return res.data.data;
  }

  public async resetSystemConfig(): Promise<SystemConfig> {
    const res = await this.client.post<{ success: boolean; data: SystemConfig }>('/settings/reset');
    return res.data.data;
  }

  public async listApiKeys(): Promise<ApiKeyItem[]> {
    const res = await this.client.get<{ success: boolean; data: ApiKeyItem[] }>('/settings/api-keys');
    return res.data.data;
  }

  public async createApiKey(req: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    const res = await this.client.post<{ success: boolean; data: CreateApiKeyResponse }>('/settings/api-keys', req);
    return res.data.data;
  }

  public async revokeApiKey(id: string): Promise<boolean> {
    const res = await this.client.delete<{ success: boolean }>(`/settings/api-keys/${id}`);
    return res.data.success;
  }

  public async getAuditLogs(filters?: { category?: string; severity?: string; actor?: string; search?: string; limit?: number; offset?: number }): Promise<{ total: number; logs: AuditLogEntry[] }> {
    const params = new URLSearchParams();
    if (filters?.category) params.append('category', filters.category);
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.actor) params.append('actor', filters.actor);
    if (filters?.search) params.append('search', filters.search);
    if (filters?.limit) params.append('limit', String(filters.limit));
    if (filters?.offset) params.append('offset', String(filters.offset));

    const res = await this.client.get<{ success: boolean; data: { total: number; logs: AuditLogEntry[] } }>(`/audit-logs?${params.toString()}`);
    return res.data.data;
  }

  public async listThreatFeeds(): Promise<ThreatFeedStatus[]> {
    const res = await this.client.get<{ success: boolean; data: ThreatFeedStatus[] }>('/feeds');
    return res.data.data;
  }

  public async syncThreatFeed(source: string): Promise<ThreatFeedSyncResult> {
    const res = await this.client.post<{ success: boolean; data: ThreatFeedSyncResult }>(`/feeds/${source}/sync`);
    return res.data.data;
  }

  public async syncAllThreatFeeds(): Promise<ThreatFeedSyncResult[]> {
    const res = await this.client.post<{ success: boolean; data: ThreatFeedSyncResult[] }>('/feeds/sync-all');
    return res.data.data;
  }

  public async toggleThreatFeed(source: string, enabled: boolean): Promise<ThreatFeedStatus> {
    const res = await this.client.patch<{ success: boolean; data: ThreatFeedStatus }>(`/feeds/${source}/toggle`, { enabled });
    return res.data.data;
  }

  // --- Milestone 10: Threat Simulation & Red Team Replay ---
  public async listSimulationPresets(): Promise<AttackScenarioPreset[]> {
    const res = await this.client.get<{ success: boolean; data: AttackScenarioPreset[] }>('/simulation/presets');
    return res.data.data;
  }

  public async runAttackSimulation(req: AttackSimulationRequest): Promise<AttackSimulationResult> {
    const res = await this.client.post<{ success: boolean; data: AttackSimulationResult }>('/simulation/run', req);
    return res.data.data;
  }

  public async runDefenseBenchmark(): Promise<DefenseBenchmarkReport> {
    const res = await this.client.post<{ success: boolean; data: DefenseBenchmarkReport }>('/simulation/benchmark');
    return res.data.data;
  }

  // --- Milestone 12: Takedown Dispatcher & Legal Abuse Center ---
  public async listTakedowns(status?: string): Promise<TakedownNotice[]> {
    const res = await this.client.get<{ success: boolean; data: TakedownNotice[] }>(`/takedowns${status ? `?status=${status}` : ''}`);
    return res.data.data;
  }

  public async getTakedown(id: string): Promise<TakedownNotice> {
    const res = await this.client.get<{ success: boolean; data: TakedownNotice }>(`/takedowns/${id}`);
    return res.data.data;
  }

  public async createTakedown(req: CreateTakedownRequest): Promise<TakedownNotice> {
    const res = await this.client.post<{ success: boolean; data: TakedownNotice }>('/takedowns', req);
    return res.data.data;
  }

  public async updateTakedownStatus(id: string, status: string): Promise<TakedownNotice> {
    const res = await this.client.patch<{ success: boolean; data: TakedownNotice }>(`/takedowns/${id}/status`, { status });
    return res.data.data;
  }

  // --- Milestone 12: Organization & Team Workspaces ---
  public async getWorkspace(): Promise<OrganizationWorkspace> {
    const res = await this.client.get<{ success: boolean; data: OrganizationWorkspace }>('/organizations/workspace');
    return res.data.data;
  }

  public async updateWorkspacePolicy(policy: Partial<OrganizationWorkspace['securityPolicy']>): Promise<OrganizationWorkspace> {
    const res = await this.client.patch<{ success: boolean; data: OrganizationWorkspace }>('/organizations/policy', policy);
    return res.data.data;
  }

  public async inviteTeamMember(name: string, email: string, role: OrganizationRole): Promise<TeamMember> {
    const res = await this.client.post<{ success: boolean; data: TeamMember }>('/organizations/members', { name, email, role });
    return res.data.data;
  }

  public async removeTeamMember(memberId: string): Promise<boolean> {
    const res = await this.client.delete<{ success: boolean }>(`/organizations/members/${memberId}`);
    return res.data.success;
  }

  // --- Milestone 12: Executive Threat Intelligence Briefings ---
  public async getExecutiveReport(timeRange = 'Last 30 Days'): Promise<ExecutiveThreatReport> {
    const res = await this.client.get<{ success: boolean; data: ExecutiveThreatReport }>(`/reports/executive?timeRange=${encodeURIComponent(timeRange)}`);
    return res.data.data;
  }

  // --- Health Check ---
  public async getHealth(): Promise<any> {
    const res = await this.client.get('/health');
    return res.data;
  }
}

export const api = new ApiService();



