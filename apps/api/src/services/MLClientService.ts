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
    let hostname = '';
    let pathname = '';
    let search = '';
    let subdomains = 0;
    let tldLength = 3;

    try {
      const parsed = new URL(url.startsWith('http') ? url : `http://${url}`);
      hasHttps = parsed.protocol === 'https:' ? 1 : 0;
      hostname = parsed.hostname;
      pathname = parsed.pathname;
      search = parsed.search;

      const hostParts = hostname.split('.');
      if (hostParts.length > 2) {
        subdomains = hostParts.length - 2;
      }
      if (hostParts.length > 1) {
        tldLength = hostParts[hostParts.length - 1].length;
      }
    } catch {
      hostname = url.split('/')[0] || '';
    }

    const hasIp = /(\d{1,3}\.){3}\d{1,3}/.test(url) ? 1 : 0;
    const suspiciousKeywords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'bank', 'paypal', 'wallet'];
    const keywordMatches = suspiciousKeywords.filter(kw => url.toLowerCase().includes(kw)).length;

    // Accurate Shannon entropy calculation
    const charFrequencies: Record<string, number> = {};
    for (let i = 0; i < url.length; i++) {
      const c = url[i];
      charFrequencies[c] = (charFrequencies[c] || 0) + 1;
    }
    let calculatedEntropy = 0;
    for (const count of Object.values(charFrequencies)) {
      const p = count / url.length;
      calculatedEntropy -= p * Math.log2(p);
    }
    const entropy = Math.round(calculatedEntropy * 100) / 100;

    const specialChars = (url.match(/[^a-zA-Z0-9]/g) || []).length;
    const digits = (url.match(/\d/g) || []).length;
    const hyphens = (url.match(/-/g) || []).length;

    let prob = 0.05;
    if (hasIp) prob += 0.45;
    if (keywordMatches > 0) prob += Math.min(0.40, keywordMatches * 0.15);
    if (!hasHttps) prob += 0.15;
    if (entropy > 4.5) prob += 0.15;
    if (subdomains >= 2) prob += 0.10;

    const finalProb = Math.min(0.99, Math.max(0.01, prob));

    return {
      url: rawUrl,
      normalized_url: rawUrl,
      features: {
        url_length: url.length,
        hostname_length: hostname.length,
        path_length: pathname.length,
        query_length: search.length,
        subdomain_count: subdomains,
        has_ip_address: hasIp,
        has_https: hasHttps,
        special_char_count: specialChars,
        digit_count: digits,
        hyphen_count: hyphens,
        at_symbol_count: url.includes('@') ? 1 : 0,
        double_slash_in_path: pathname.includes('//') ? 1 : 0,
        encoded_char_count: (url.match(/%[0-9a-fA-F]{2}/g) || []).length,
        suspicious_keyword_count: keywordMatches,
        entropy,
        tld_in_subdomain: 0,
        port_in_url: (url.match(/:\d{2,5}/) ? 1 : 0),
        tld_length: tldLength
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
