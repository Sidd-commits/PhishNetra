import request from 'supertest';
import { createApp } from '../src/app';

const app = createApp();

describe('Multimodal Quishing Defense, Threat Attribution & FAIR Risk Suite (Milestone 17)', () => {
  describe('Multimodal Quishing (QR Code) Defense (/api/quishing)', () => {
    it('should return simulated test samples', async () => {
      const res = await request(app).get('/api/quishing/samples');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(3);
    });

    it('should detect benign QR payload and return low risk score', async () => {
      const res = await request(app)
        .post('/api/quishing/scan')
        .send({
          imageUrl: 'https://images.example.com/menu-qr-code.png',
          rawText: 'Restaurant digital dinner menu. Scan to view our wine list and appetizers.'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.qrDetected).toBe(true);
      expect(res.body.data.isQuishingAttack).toBe(false);
      expect(res.body.data.riskScore).toBeLessThan(70);
    });

    it('should identify active Quishing credential attack with MFA visual lure and generate Snort rule', async () => {
      const res = await request(app)
        .post('/api/quishing/scan')
        .send({
          imageUrl: 'https://malicious-lure.net/qr-okta-auth.png',
          rawText: 'Urgent: Microsoft 365 session expired. Scan to update your Authenticator app now to avoid immediate account suspension.',
          deepScanPayload: true
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.qrDetected).toBe(true);
      expect(res.body.data.isQuishingAttack).toBe(true);
      expect(res.body.data.verdict).toBe('PHISHING');
      expect(res.body.data.mitigationPayload.fido2Enforced).toBe(true);
      expect(res.body.data.mitigationPayload.snortRule).toContain('PHISHNETRA_QUISHING');
      expect(res.body.data.visualLures.length).toBeGreaterThanOrEqual(1);
    });

    it('should handle invalid request body gracefully', async () => {
      const res = await request(app)
        .post('/api/quishing/scan')
        .send({ ocrExtract: 'invalid_boolean' as any });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  describe('Adversary & Threat Actor Attribution Matrix (/api/attribution)', () => {
    it('should list all tracked threat actor profiles', async () => {
      const res = await request(app).get('/api/attribution/actors');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.some((a: any) => a.actorId === 'SCATTERED_SPIDER')).toBe(true);
      expect(res.body.data.some((a: any) => a.actorId === 'APT28')).toBe(true);
      expect(res.body.data.some((a: any) => a.actorId === 'LAZARUS_GROUP')).toBe(true);
    });

    it('should retrieve a specific threat actor profile by ID', async () => {
      const res = await request(app).get('/api/attribution/actors/APT29');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.actorId).toBe('APT29');
      expect(res.body.data.actorName).toContain('Midnight Blizzard');
    });

    it('should return 404 for unknown actor ID', async () => {
      const res = await request(app).get('/api/attribution/actors/UNKNOWN_HACKER_GROUP');
      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
    });

    it('should match candidate domain and TTPs against threat actor matrix', async () => {
      const res = await request(app)
        .post('/api/attribution/match')
        .send({
          targetDomain: 'identity-okta-sso-verify.live',
          ttps: ['T1566.002', 'T1621', 'T1583.001'],
          asn: 'AS13335'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.targetDomain).toBe('identity-okta-sso-verify.live');
      expect(res.body.data.topMatches.length).toBeGreaterThanOrEqual(1);

      const topMatch = res.body.data.topMatches[0];
      expect(topMatch.actorId).toBe('SCATTERED_SPIDER');
      expect(topMatch.attributionConfidence).toBeGreaterThanOrEqual(60);
      expect(topMatch.adversaryDiamondModel).toHaveProperty('adversary');
      expect(topMatch.adversaryDiamondModel).toHaveProperty('infrastructure');
    });
  });

  describe('Quantitative Cyber Risk (FAIR Model) (/api/risk-quantification)', () => {
    it('should return benchmark parameter defaults', async () => {
      const res = await request(app).get('/api/risk-quantification/defaults');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.annualPhishingAttempts).toBe(5000);
      expect(res.body.data.susceptibilityRate).toBe(0.12);
    });

    it('should calculate FAIR quantitative risk with loss distribution and ROI multiple', async () => {
      const res = await request(app)
        .post('/api/risk-quantification/calculate')
        .send({
          annualPhishingAttempts: 10000,
          susceptibilityRate: 0.15,
          controlEffectiveness: 0.88,
          averageEmployeeCount: 1200,
          costPerCompromisedCredential: 5000,
          secondaryRegulatoryFineLikelihood: 0.20,
          maxRegulatoryFine: 5000000
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('lossEventFrequency');
      expect(res.body.data).toHaveProperty('totalExpectedAnnualLoss');
      expect(res.body.data).toHaveProperty('annualLossMitigatedByPhishNetra');
      expect(res.body.data).toHaveProperty('defenseRoiMultiple');
      expect(res.body.data.defenseRoiMultiple).toBeGreaterThan(0);
      expect(res.body.data.lossDistribution).toHaveProperty('tenthPercentile');
      expect(res.body.data.lossDistribution).toHaveProperty('ninetiethPercentile');
    });

    it('should classify high exposure scenarios into CRITICAL risk tier', async () => {
      const res = await request(app)
        .post('/api/risk-quantification/calculate')
        .send({
          annualPhishingAttempts: 50000,
          susceptibilityRate: 0.35,
          controlEffectiveness: 0.30, // weak controls
          costPerCompromisedCredential: 8000,
          maxRegulatoryFine: 10000000
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.riskTier).toBe('CRITICAL');
      expect(res.body.data.totalExpectedAnnualLoss).toBeGreaterThan(1000000);
    });
  });
});
