import request from 'supertest';
import { createApp } from '../src/app';
import jwt from 'jsonwebtoken';
import { config } from '../src/config/env';

const app = createApp();

const generateTestToken = (role: string = 'ANALYST') => {
  return jwt.sign(
    {
      userId: 'usr-analyst-test',
      email: 'analyst@phishnetra.security',
      role,
      name: 'SOC Analyst'
    },
    config.jwt.secret,
    { expiresIn: '1h' }
  );
};

describe('AI SOC Co-Pilot, Canary Deception & EASM Suite (Milestone 14)', () => {
  const token = generateTestToken();

  describe('AI SOC Co-Pilot Assistant (/api/copilot)', () => {
    it('should list pre-configured SOC prompt templates', async () => {
      const res = await request(app)
        .get('/api/copilot/templates')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(4);
      expect(res.body.data[0]).toHaveProperty('id');
      expect(res.body.data[0]).toHaveProperty('title');
      expect(res.body.data[0]).toHaveProperty('prompt');
    });

    it('should process analyst inquiry and return multi-step reasoning with defense artifacts', async () => {
      const res = await request(app)
        .post('/api/copilot/chat')
        .set('Authorization', `Bearer ${token}`)
        .send({
          prompt: 'Analyze this suspicious Microsoft login portal and compile hunting rules.',
          sessionType: 'TRIAGE',
          context: {
            domain: 'auth-sec-verify-microsoft.account-portal.xyz',
            targetUrl: 'https://auth-sec-verify-microsoft.account-portal.xyz/login',
            brand: 'Microsoft',
            riskScore: 96.5,
            verdict: 'PHISHING'
          }
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data).toHaveProperty('reply');
      expect(res.body.data.reply).toContain('PhishNetra AI SOC Co-Pilot Assessment');
      expect(Array.isArray(res.body.data.reasoningSteps)).toBe(true);
      expect(res.body.data.reasoningSteps.length).toBeGreaterThanOrEqual(3);
      expect(Array.isArray(res.body.data.suggestedActions)).toBe(true);
      expect(res.body.data.suggestedActions.length).toBeGreaterThanOrEqual(2);
      expect(res.body.data.generatedArtifacts).toHaveProperty('huntQuery');
      expect(res.body.data.generatedArtifacts).toHaveProperty('snortRule');
      expect(res.body.data.generatedArtifacts).toHaveProperty('siemKqlQuery');
      expect(res.body.data.generatedArtifacts).toHaveProperty('dnsRpzEntry');
      expect(Array.isArray(res.body.data.mitreTechniques)).toBe(true);
      expect(res.body.data.mitreTechniques.some((m: any) => m.id === 'T1566.002')).toBe(true);
    });
  });

  describe('Active Canary Deception Engine (/api/deception)', () => {
    let createdTokenId = '';

    it('should list all active canary deception tokens', async () => {
      const res = await request(app)
        .get('/api/deception/tokens')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(3);
      expect(res.body.data[0]).toHaveProperty('deploySnippet');
    });

    it('should create a new canary tripwire token', async () => {
      const res = await request(app)
        .post('/api/deception/tokens')
        .set('Authorization', `Bearer ${token}`)
        .send({
          name: 'Decoy Git Secret Canary',
          tokenType: 'FAKE_API_KEY',
          targetDeployLocation: 'staging-api/.env.example',
          alertSeverity: 'CRITICAL',
          customNotes: 'Decoy API key in public repo'
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data.tokenType).toBe('FAKE_API_KEY');
      expect(res.body.data.deploySnippet).toContain('PHISHNETRA_CANARY_KEY');
      createdTokenId = res.body.data.id;
    });

    it('should toggle canary token status to DISABLED', async () => {
      const res = await request(app)
        .patch(`/api/deception/tokens/${createdTokenId}/status`)
        .set('Authorization', `Bearer ${token}`)
        .send({ status: 'DISABLED' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('DISABLED');
    });

    it('should record a tripwire trigger via the public HTTP beacon endpoint', async () => {
      const beaconRes = await request(app)
        .get('/api/deception/beacon/tok_webbug_9f82a1c.gif')
        .set('User-Agent', 'ThreatActor-Scraper-Bot/1.0')
        .set('Referer', 'https://phishing-attacker-drop.com/login');

      expect(beaconRes.status).toBe(200);
      expect(beaconRes.headers['content-type']).toContain('image/gif');

      // Check that the trigger was recorded
      const triggersRes = await request(app)
        .get('/api/deception/triggers')
        .set('Authorization', `Bearer ${token}`);

      expect(triggersRes.status).toBe(200);
      expect(triggersRes.body.success).toBe(true);
      expect(Array.isArray(triggersRes.body.data)).toBe(true);
      expect(triggersRes.body.data.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('External Attack Surface Management & CT Logs (/api/attack-surface)', () => {
    let newAssetId = '';

    it('should list all perimeter attack surface assets', async () => {
      const res = await request(app)
        .get('/api/attack-surface/assets')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(4);
    });

    it('should add a new monitored perimeter asset', async () => {
      const res = await request(app)
        .post('/api/attack-surface/assets')
        .set('Authorization', `Bearer ${token}`)
        .send({
          name: 'Staging OAuth Callback Gateway',
          assetType: 'SUBDOMAIN',
          targetValue: 'oauth-staging.phishnetra.security',
          associatedBrands: ['PhishNetra']
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data.assetType).toBe('SUBDOMAIN');
      newAssetId = res.body.data.id;
    });

    it('should list Certificate Transparency (CT) log stream entries', async () => {
      const res = await request(app)
        .get('/api/attack-surface/ct-logs')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.some((e: any) => e.isTyposquat === true)).toBe(true);
    });

    it('should trigger a live perimeter scan sweep', async () => {
      const res = await request(app)
        .post('/api/attack-surface/scan')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('totalAssets');
      expect(res.body.data).toHaveProperty('scannedAt');
    });

    it('should delete a perimeter asset', async () => {
      const res = await request(app)
        .delete(`/api/attack-surface/assets/${newAssetId}`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });
});
