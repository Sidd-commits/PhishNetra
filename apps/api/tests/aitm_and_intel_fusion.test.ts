import request from 'supertest';
import { createApp } from '../src/app';

const app = createApp();

describe('AiTM Reverse Proxy Defense, Threat Intel Fusion & Compliance Suite (Milestone 16)', () => {
  describe('Adversary-in-the-Middle (AiTM) Reverse Proxy Defense (/api/aitm)', () => {
    it('should evaluate a benign web target and return clean verdict', async () => {
      const res = await request(app)
        .post('/api/aitm/scan')
        .send({
          targetUrl: 'https://legitimate-corp.example.com/portal',
          claimedHost: 'legitimate-corp.example.com'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.isAiTMProxy).toBe(false);
      expect(res.body.data.recommendedAction).toBe('ALLOW');
      expect(res.body.data.riskScore).toBeLessThan(40);
    });

    it('should detect Evilginx reverse proxy with enterprise domain binding tunneling and cookie interception', async () => {
      const res = await request(app)
        .post('/api/aitm/scan')
        .send({
          targetUrl: 'https://login.microsoftonline.com.evil-reverse-proxy.xyz/login',
          claimedHost: 'login.microsoftonline.com',
          headers: {
            'x-forwarded-host': 'login.microsoftonline.com',
            'x-evilginx-client-ip': '203.0.113.19'
          },
          cookiesPresent: ['ESTSAUTH', 'session_token', 'remember_token']
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.isAiTMProxy).toBe(true);
      expect(res.body.data.riskScore).toBeGreaterThanOrEqual(90);
      expect(res.body.data.recommendedAction).toBe('BLOCK_AND_INVALIDATE');
      expect(res.body.data.indicators.length).toBeGreaterThan(0);
      expect(res.body.data.mitigationArtifact).toContain('REVOKE_SESSION_ID');
      expect(res.body.data.mitigationArtifact).toContain('ENFORCE_PASSKEY_FIDO2_CREDENTIAL_BOUND_AUTHENTICATION');
    });

    it('should detect header injection anomalies on proxy relay', async () => {
      const res = await request(app)
        .post('/api/aitm/scan')
        .send({
          targetUrl: 'https://proxy-relay.suspicious-gateway.net/auth',
          headers: {
            'x-forwarded-host': 'unrelated-internal-service.local'
          }
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.indicators.some((i: any) => i.type === 'HEADER_INJECTION_ANOMALY')).toBe(true);
    });
  });

  describe('Threat Intelligence Fusion & Bayesian Half-Life Decay (/api/intel-fusion)', () => {
    it('should list pre-seeded multi-source fused IOC entries', async () => {
      const res = await request(app).get('/api/intel-fusion');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThan(0);
      expect(res.body.data[0]).toHaveProperty('decayedScore');
    });

    it('should score and ingest a new IOC with Bayesian decay properties', async () => {
      const res = await request(app)
        .post('/api/intel-fusion/score')
        .send({
          iocValue: '198.51.100.42',
          iocType: 'IP',
          sourceFeeds: ['URLHAUS', 'OPENPHISH', 'CISA_KEV']
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.iocValue).toBe('198.51.100.42');
      expect(res.body.data.baseScore).toBeGreaterThanOrEqual(80);
      expect(res.body.data.halfLifeHours).toBe(24);
      expect(res.body.data.status).toBe('ACTIVE');
    });

    it('should get and update Bayesian decay configuration', async () => {
      const getRes = await request(app).get('/api/intel-fusion/config');
      expect(getRes.status).toBe(200);
      expect(getRes.body.data).toHaveProperty('fastFluxIpHalfLifeHours');

      const patchRes = await request(app)
        .patch('/api/intel-fusion/config')
        .send({
          fastFluxIpHalfLifeHours: 12,
          decayFloorScore: 10
        });

      expect(patchRes.status).toBe(200);
      expect(patchRes.body.data.fastFluxIpHalfLifeHours).toBe(12);
      expect(patchRes.body.data.decayFloorScore).toBe(10);
    });
  });

  describe('Enterprise Compliance & Posture Audit (/api/compliance)', () => {
    it('should execute NIST CSF 2.0 posture compliance audit', async () => {
      const res = await request(app).get('/api/compliance/audit?framework=NIST_CSF_2');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.framework).toBe('NIST_CSF_2');
      expect(res.body.data.overallCompliancePercent).toBeGreaterThanOrEqual(90);
      expect(res.body.data.controls.length).toBeGreaterThan(0);
      expect(res.body.data.executiveSummary).toContain('NIST_CSF_2');
    });

    it('should execute SOC 2 Type II posture compliance audit', async () => {
      const res = await request(app).get('/api/compliance/audit?framework=SOC_2_TYPE_II');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.framework).toBe('SOC_2_TYPE_II');
      expect(res.body.data.overallCompliancePercent).toBeGreaterThanOrEqual(90);
      expect(res.body.data.controls.some((c: any) => c.controlId === 'CC6.6')).toBe(true);
    });
  });
});
