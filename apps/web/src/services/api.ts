import axios, { AxiosInstance } from 'axios';
import {
  AuthResponse,
  LoginRequest,
  RegisterRequest,
  AnalysisResponse,
  AnalysisSummary,
  UserProfile
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

  // --- Health Check ---
  public async getHealth(): Promise<any> {
    const res = await this.client.get('/health');
    return res.data;
  }
}

export const api = new ApiService();
