import axios, { AxiosInstance } from 'axios';
import { config } from '../config/env';
import {
  MLPredictionResponse,
  MLPredictionResponseSchema
} from '@phishnetra/shared';

export class MLClientService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: config.mlService.url,
      timeout: config.mlService.timeoutMs,
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }

  public async predictURL(url: string): Promise<MLPredictionResponse> {
    try {
      const response = await this.client.post('/api/v1/predict', { url });
      const parsed = MLPredictionResponseSchema.parse(response.data);
      return parsed;
    } catch (error: any) {
      console.warn(`[MLClientService] ML Service call failed (${error.message}). Falling back to local heuristic extraction.`);
      return this.localHeuristicFallback(url);
    }
  }

  public async checkHealth(): Promise<{ status: string; details?: any }> {
    try {
      const response = await this.client.get('/health');
      return { status: 'connected', details: response.data };
    } catch (error: any) {
      return { status: 'disconnected', details: error.message };
    }
  }

  private localHeuristicFallback(rawUrl: string): MLPredictionResponse {
    const url = rawUrl.trim();
    let hasHttps = 0;
    try {
      const parsed = new URL(url);
      hasHttps = parsed.protocol === 'https:' ? 1 : 0;
    } catch {
      // ignore
    }

    const hasIp = /(\d{1,3}\.){3}\d{1,3}/.test(url) ? 1 : 0;
    const suspiciousKeywords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'bank', 'paypal', 'wallet'];
    const keywordMatches = suspiciousKeywords.filter(kw => url.toLowerCase().includes(kw)).length;

    let prob = 0.05;
    if (hasIp) prob += 0.45;
    if (keywordMatches > 0) prob += Math.min(0.40, keywordMatches * 0.15);
    if (!hasHttps) prob += 0.15;

    const finalProb = Math.min(0.99, Math.max(0.01, prob));

    return {
      url: rawUrl,
      normalized_url: rawUrl,
      features: {
        url_length: url.length,
        hostname_length: 20,
        path_length: 10,
        query_length: 0,
        subdomain_count: 1,
        has_ip_address: hasIp,
        has_https: hasHttps,
        special_char_count: 3,
        digit_count: 2,
        hyphen_count: 1,
        at_symbol_count: url.includes('@') ? 1 : 0,
        double_slash_in_path: 0,
        encoded_char_count: 0,
        suspicious_keyword_count: keywordMatches,
        entropy: 3.5,
        tld_in_subdomain: 0,
        port_in_url: 0,
        tld_length: 3
      },
      phishing_probability: Math.round(finalProb * 1000) / 1000,
      confidence: Math.round(Math.abs(finalProb - 0.5) * 2 * 1000) / 1000,
      predicted_label: finalProb >= 0.5 ? 1 : 0,
      model_version: 'v0.1.0-fallback',
      inference_time_ms: 1.2
    };
  }
}

export const mlClientService = new MLClientService();
export const mlClient = mlClientService;
