import request from 'supertest';
import { createApp } from '../src/app';
import { prisma } from '../src/db/prisma';
import { riskEngine } from '../src/services/RiskEngine';
import { analysisService } from '../src/services/AnalysisService';

const app = createApp();

describe('Analysis & Risk Engine Test Suite', () => {
  beforeAll(async () => {
    try {
      await prisma.$connect();
    } catch {
      // Mock prisma analysis methods for local test isolation
      const analyses: any[] = [];
      jest.spyOn(prisma.analysis, 'create').mockImplementation((({ data }: any) => {
        const id = `ana_${Date.now()}`;
        const record = {
          id,
          userId: data.userId || null,
          url: data.url,
          normalizedUrl: data.normalizedUrl,
          verdict: data.verdict,
          riskScore: data.riskScore,
          riskLevel: data.riskLevel,
          confidence: data.confidence,
          mlProbability: data.mlProbability,
          status: 'COMPLETED',
          createdAt: new Date(),
          updatedAt: new Date(),
          evidence: data.evidence?.create || []
        };
        analyses.push(record);
        return Promise.resolve(record);
      }) as any);

      jest.spyOn(prisma.analysis, 'findUnique').mockImplementation((({ where }: any) => {
        const found = analyses.find(a => a.id === where.id);
        return Promise.resolve(found || null);
      }) as any);
    }
  });

  afterAll(async () => {
    try {
      await prisma.$disconnect();
    } catch {
      // ignore
    }
  });

  describe('URL Normalization', () => {
    it('should prepend http:// scheme if omitted', () => {
      expect(analysisService.normalizeUrl('example.com')).toBe('http://example.com/');
    });

    it('should lowercase hostname and strip default port 80/443', () => {
      expect(analysisService.normalizeUrl('HTTPS://EXAMPLE.COM:443/login')).toBe('https://example.com/login');
      expect(analysisService.normalizeUrl('http://EXAMPLE.COM:80/path')).toBe('http://example.com/path');
    });
  });

  describe('RiskEngine Unit Tests', () => {
    it('should classify safe URLs with low risk score and SAFE verdict', () => {
      const result = riskEngine.evaluate(
        0.02,
        0.96,
        {
          url_length: 22,
          hostname_length: 10,
          path_length: 1,
          query_length: 0,
          subdomain_count: 0,
          has_ip_address: 0,
          has_https: 1,
          special_char_count: 3,
          digit_count: 0,
          hyphen_count: 0,
          at_symbol_count: 0,
          double_slash_in_path: 0,
          encoded_char_count: 0,
          suspicious_keyword_count: 0,
          entropy: 3.1,
          tld_in_subdomain: 0,
          port_in_url: 0,
          tld_length: 3
        }
      );

      expect(result.verdict).toBe('SAFE');
      expect(result.riskLevel).toBe('LOW');
      expect(result.riskScore).toBeLessThan(30);
      expect(result.evidence.length).toBeGreaterThan(0);
    });

    it('should classify IP hostnames with phishing keywords as PHISHING/CRITICAL', () => {
      const result = riskEngine.evaluate(
        0.95,
        0.90,
        {
          url_length: 65,
          hostname_length: 13,
          path_length: 30,
          query_length: 10,
          subdomain_count: 0,
          has_ip_address: 1,
          has_https: 0,
          special_char_count: 8,
          digit_count: 12,
          hyphen_count: 2,
          at_symbol_count: 0,
          double_slash_in_path: 0,
          encoded_char_count: 0,
          suspicious_keyword_count: 3, // paypal, login, verify
          entropy: 4.8,
          tld_in_subdomain: 0,
          port_in_url: 0,
          tld_length: 0
        }
      );

      expect(result.verdict).toBe('PHISHING');
      expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
      expect(result.riskScore).toBeGreaterThanOrEqual(60);
      expect(result.evidence.some(e => e.featureKey === 'has_ip_address')).toBe(true);
      expect(result.evidence.some(e => e.featureKey === 'suspicious_keyword_count')).toBe(true);
    });
  });

  describe('POST /api/analyze Endpoint', () => {
    it('should reject malformed or non-URL inputs', async () => {
      const res = await request(app)
        .post('/api/analyze')
        .send({ url: 'not-a-valid-url-format' });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'Validation Error');
    });

    it('should process a valid URL and return analysis result with evidence', async () => {
      const res = await request(app)
        .post('/api/analyze')
        .send({ url: 'https://example.com/login' });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('analysisId');
      expect(res.body).toHaveProperty('verdict');
      expect(res.body).toHaveProperty('riskScore');
      expect(res.body).toHaveProperty('confidence');
      expect(res.body).toHaveProperty('evidence');
      expect(Array.isArray(res.body.evidence)).toBe(true);
    });
  });
});
