/**
 * PhishNetra - Page Analyzer Client Service
 * Module: apps.api.src.services.PageAnalyzerClient
 * Milestone: 3
 */
import axios, { AxiosInstance } from 'axios';
import { config } from '../config/env';
import {
  PageAnalysisResult,
  PageAnalysisResultSchema
} from '@phishnetra/shared';

export class PageAnalyzerClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: config.mlService.url,
      timeout: 15000,
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }

  /**
   * Invokes the isolated secure page analyzer microservice.
   */
  public async analyzePage(url: string, captureScreenshot = false): Promise<PageAnalysisResult> {
    try {
      const response = await this.client.post('/api/v1/analyze-page', {
        url,
        timeout_ms: 10000,
        capture_screenshot: captureScreenshot
      });

      const parsed = PageAnalysisResultSchema.parse(response.data);
      return parsed;
    } catch (error: any) {
      console.warn(`[PageAnalyzerClient] Microservice call failed (${error.message}). Applying graceful fallback.`);
      return this.localFallback(url, error.message);
    }
  }

  /**
   * Fallback for test environments or microservice unavailability.
   */
  private localFallback(rawUrl: string, reason: string): PageAnalysisResult {
    const isPrivate = /(^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.))/i.test(rawUrl);

    if (isPrivate) {
      return {
        status: 'BLOCKED',
        requestedUrl: rawUrl,
        finalUrl: rawUrl,
        redirectCount: 0,
        redirectChain: [],
        forms: [],
        iframes: [],
        scripts: [],
        keywords: [],
        brandFindings: [],
        urgencyScore: 0,
        contentRiskScore: 95.0,
        phishingProbability: 0.95,
        confidence: 1.0,
        error: 'Destination resolved to prohibited RFC1918 / loopback IP address',
        blockReason: 'Target falls within prohibited private or loopback IP range (SSRF Shield)',
        acquisitionTimeMs: 1.0
      };
    }

    return {
      status: 'FAILED',
      requestedUrl: rawUrl,
      finalUrl: rawUrl,
      redirectCount: 0,
      redirectChain: [],
      forms: [],
      iframes: [],
      scripts: [],
      keywords: [],
      brandFindings: [],
      urgencyScore: 0,
      contentRiskScore: 0,
      phishingProbability: 0,
      confidence: 0.5,
      error: `Page inspection unavailable: ${reason}`,
      blockReason: null,
      acquisitionTimeMs: 0.0
    };
  }
}

export const pageAnalyzerClient = new PageAnalyzerClient();
