import request from 'supertest';
import { createApp } from '../src/app';

const app = createApp();

describe('Threat Simulation & Red Team Attack Replay Suite (Milestone 10)', () => {
  describe('GET /api/simulation/presets', () => {
    it('should list all pre-configured Red Team attack scenarios', async () => {
      const res = await request(app).get('/api/simulation/presets');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeInstanceOf(Array);
      expect(res.body.data.length).toBeGreaterThanOrEqual(4);

      const msPreset = res.body.data.find((p: any) => p.id === 'preset_ms365_urgency');
      expect(msPreset).toBeDefined();
      expect(msPreset.targetBrand).toBe('Microsoft');
      expect(msPreset.expectedVerdict).toBe('PHISHING');
    });
  });

  describe('POST /api/simulation/run', () => {
    it('should simulate Spear Phishing with Brand Impersonation and trigger Zero-Trust overrides', async () => {
      const res = await request(app)
        .post('/api/simulation/run')
        .send({
          presetId: 'preset_ms365_urgency',
          targetUrl: 'https://login.microsoftonline.com-security-auth.net/re-verify',
          targetBrand: 'Microsoft',
          vectorType: 'SPEAR_PHISH_BRAND_IMPERSONATION'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.simulationId).toBeDefined();
      expect(res.body.data.verdict).toBe('PHISHING');
      expect(res.body.data.riskLevel).toBe('CRITICAL');
      expect(res.body.data.isMitigated).toBe(true);
      expect(res.body.data.zeroTrustHolding).toBe(true);
      expect(res.body.data.layerSteps.length).toBe(8);
      expect(res.body.data.generatedEvidence.length).toBeGreaterThanOrEqual(1);
    });

    it('should simulate SSRF Metadata Probe and ensure active defense blocking', async () => {
      const res = await request(app)
        .post('/api/simulation/run')
        .send({
          presetId: 'preset_ssrf_metadata',
          targetUrl: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
          vectorType: 'SSRF_METADATA_PROBE'
        });

      expect(res.status).toBe(200);
      expect(res.body.data.verdict).toBe('PHISHING');
      expect(res.body.data.totalRiskScore).toBeGreaterThanOrEqual(85);
      expect(res.body.data.isMitigated).toBe(true);
    });

    it('should simulate Unicode Homoglyph Attack and detect confusable character deception', async () => {
      const res = await request(app)
        .post('/api/simulation/run')
        .send({
          presetId: 'preset_paypal_homoglyph',
          targetUrl: 'http://pаypal.com/cgi-bin/webscr-login?account_id=98314',
          targetBrand: 'PayPal',
          vectorType: 'UNICODE_HOMOGLYPH_PUNYCODE'
        });

      expect(res.status).toBe(200);
      expect(res.body.data.verdict).toBe('PHISHING');
      expect(res.body.data.generatedEvidence.some((e: any) => e.featureKey === 'HOMOGLYPH_CONFUSABLE_DETECTED')).toBe(true);
    });
  });

  describe('POST /api/simulation/benchmark', () => {
    it('should execute automated Red Team benchmark across all 12 vector families', async () => {
      const res = await request(app).post('/api/simulation/benchmark');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.benchmarkId).toBeDefined();
      expect(res.body.data.totalScenariosTested).toBeGreaterThanOrEqual(40);
      expect(res.body.data.mitigationRatePercent).toBeGreaterThanOrEqual(90);
      expect(res.body.data.zeroTrustInvariantIntegrity).toBe(100.0);
      expect(res.body.data.vectorBreakdown).toBeInstanceOf(Array);
      expect(res.body.data.vectorBreakdown.length).toBe(12);
    });
  });
});
