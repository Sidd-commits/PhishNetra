import request from 'supertest';
import { createApp } from '../src/app';
import { prisma } from '../src/db/prisma';
import { canonicalizeUrl } from '../src/services/analysis/canonicalization';

const app = createApp();

describe('Analysis & Multi-Layer Integration Test Suite', () => {
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

  describe('URL Canonicalization Engine', () => {
    it('should prepend http:// scheme if omitted', () => {
      const res = canonicalizeUrl('example.com');
      expect(res.canonicalUrl).toBe('http://example.com/');
    });

    it('should lowercase hostname and strip default port 80/443', () => {
      const res1 = canonicalizeUrl('HTTPS://EXAMPLE.COM:443/login');
      expect(res1.canonicalUrl).toBe('https://example.com/login');

      const res2 = canonicalizeUrl('http://EXAMPLE.COM:80/path');
      expect(res2.canonicalUrl).toBe('http://example.com/path');
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

    it('should process a valid URL and return multi-layer analysis result with evidence', async () => {
      const res = await request(app)
        .post('/api/analyze')
        .send({ url: 'https://example.com/login' });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('analysisId');
      expect(res.body).toHaveProperty('verdict');
      expect(res.body).toHaveProperty('riskScore');
      expect(res.body).toHaveProperty('confidence');
      expect(res.body).toHaveProperty('layers');
      expect(res.body).toHaveProperty('layerStatuses');
      expect(res.body).toHaveProperty('evidence');
      expect(Array.isArray(res.body.evidence)).toBe(true);
    });
  });
});
