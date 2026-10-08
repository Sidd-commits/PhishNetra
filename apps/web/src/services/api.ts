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
  CacheStats
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

  // --- Health Check ---
  public async getHealth(): Promise<any> {
    const res = await this.client.get('/health');
    return res.data;
  }
}

export const api = new ApiService();

