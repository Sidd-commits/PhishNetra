import request from 'supertest';
import { createApp } from '../src/app';
import { settingsService } from '../src/services/settings/SettingsService';
import { RiskEngine } from '../src/services/RiskEngine';

const app = createApp();

describe('Enterprise Governance, Calibration, Audit & Threat Feeds (Milestone 9)', () => {
  beforeEach(() => {
    settingsService.resetToDefaults('test');
  });

  describe('Dynamic Risk Engine Calibration (/api/settings)', () => {
    it('should retrieve default system configuration', async () => {
      const res = await request(app).get('/api/settings/config');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.weights.url).toBe(0.15);
      expect(res.body.data.thresholds.safeMax).toBe(35);
      expect(res.body.data.whitelistedDomains).toContain('google.com');
    });

    it('should update layer weights and threshold parameters dynamically', async () => {
      const res = await request(app)
        .patch('/api/settings/config')
        .send({
          weights: { url: 0.30, ml: 0.25 },
          thresholds: { safeMax: 40, suspiciousMax: 75 },
          whitelistedDomains: ['google.com', 'internal-corp.net']
        });

      expect(res.status).toBe(200);
      expect(res.body.data.weights.url).toBe(0.30);
      expect(res.body.data.thresholds.safeMax).toBe(40);
      expect(res.body.data.whitelistedDomains).toContain('internal-corp.net');

      // Verify that RiskEngine dynamically incorporates the updated configuration
      const engine = new RiskEngine();
      const mockInput: any = {
        urlLayer: { features: { has_ip_address: 0, suspicious_keyword_count: 0, subdomain_count: 0, tld_in_subdomain: 0 }, hasUserInfo: false, isPunycode: false, isShortener: false, hasCustomPort: false, obfuscatedEncodings: [], entropy: 3.0, status: 'SUCCESS' },
        domainLayer: { domainAgeDays: 500, status: 'SUCCESS' },
        dnsLayer: { resolvedIps: ['93.184.216.34'], status: 'SUCCESS' },
        tlsLayer: { hasTls: true, certificateValid: true, certificateExpired: false, hostnameMatches: true, status: 'SUCCESS' },
        reputationLayer: { reputationScore: 0, isListedMalicious: false, providers: [{ isConfigured: true }] },
        mlLayer: { phishingProbability: 0.05, confidence: 0.95 },
        layerEvidences: []
      };

      const result = engine.evaluateMultiLayer(mockInput);
      expect(result.verdict).toBe('SAFE');
      expect(result.riskLevel).toBe('LOW');
    });

    it('should reset system settings to default baseline', async () => {
      await request(app)
        .patch('/api/settings/config')
        .send({ weights: { url: 0.50 } });

      const resetRes = await request(app).post('/api/settings/reset');
      expect(resetRes.status).toBe(200);
      expect(resetRes.body.data.weights.url).toBe(0.15);
    });

    it('should create, list, and revoke API key tokens', async () => {
      const createRes = await request(app)
        .post('/api/settings/api-keys')
        .send({
          name: 'SIEM Integration Daemon Key',
          role: 'ADMIN',
          expiresInDays: 90
        });

      expect(createRes.status).toBe(201);
      expect(createRes.body.data.apiKey.id).toBeDefined();
      expect(createRes.body.data.secretToken).toMatch(/^phish_live_/);
      const keyId = createRes.body.data.apiKey.id;

      const listRes = await request(app).get('/api/settings/api-keys');
      expect(listRes.status).toBe(200);
      expect(listRes.body.data.some((k: any) => k.id === keyId)).toBe(true);

      const deleteRes = await request(app).delete(`/api/settings/api-keys/${keyId}`);
      expect(deleteRes.status).toBe(200);
    });
  });

  describe('SOC Audit Logging & Export (/api/audit-logs)', () => {
    it('should query audit logs with pagination and filters', async () => {
      const res = await request(app).get('/api/audit-logs?limit=10');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.logs).toBeInstanceOf(Array);
      expect(res.body.data.total).toBeGreaterThanOrEqual(1);
    });

    it('should export audit trail in CSV format', async () => {
      const res = await request(app).get('/api/audit-logs/export');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/csv');
      expect(res.text).toContain('Timestamp,Actor,Action,Category');
    });
  });

  describe('Threat Feed Synchronization Hub (/api/feeds)', () => {
    it('should list all threat intelligence feed statuses', async () => {
      const res = await request(app).get('/api/feeds');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(3);
    });

    it('should synchronize threat feed and return sync metrics', async () => {
      const res = await request(app).post('/api/feeds/URLHAUS/sync');
      expect(res.status).toBe(200);
      expect(res.body.data.source).toBe('URLHAUS');
      expect(res.body.data.status).toBe('SUCCESS');
      expect(res.body.data.newIocsAdded).toBeGreaterThan(0);
    });

    it('should toggle threat feed active status', async () => {
      const res = await request(app)
        .patch('/api/feeds/URLHAUS/toggle')
        .send({ enabled: false });

      expect(res.status).toBe(200);
      expect(res.body.data.enabled).toBe(false);
    });
  });
});
