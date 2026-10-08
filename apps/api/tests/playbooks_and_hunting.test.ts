import request from 'supertest';
import { createApp } from '../src/app';
import { authService } from '../src/services/AuthService';

describe('SOAR Playbooks, Threat Hunting & Intel Connectors (Milestone 13)', () => {
  let app: any;
  let authToken: string;

  beforeAll(async () => {
    app = createApp();
    // Register or login a test user to get JWT token
    const testEmail = `soc.hunter.${Date.now()}@phishnetra.defense`;
    const userRes = await authService.register({
      name: 'Lead SOC Hunter',
      email: testEmail,
      password: 'StrongPassword123!'
    });
    authToken = userRes.token;
  });

  describe('SOAR Playbook Orchestration (/api/playbooks)', () => {
    it('should list pre-seeded enterprise SOAR playbooks', async () => {
      const res = await request(app)
        .get('/api/playbooks')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(3);
    });

    it('should retrieve a specific playbook by ID', async () => {
      const res = await request(app)
        .get('/api/playbooks/pb_zero_day_containment')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe('pb_zero_day_containment');
      expect(res.body.data.triggerType).toBe('ON_ZERO_DAY_DISCOVERY');
    });

    it('should create a custom SOAR playbook', async () => {
      const res = await request(app)
        .post('/api/playbooks')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          name: 'Custom Lateral Movement Isolation',
          description: 'Isolates endpoints and sinkholes intranet domains upon anomalous beaconing.',
          triggerType: 'ON_HIGH_SEVERITY_INCIDENT',
          enabled: true,
          conditions: {
            minRiskScore: 80,
            targetedBrands: ['Internal-SSO'],
            requiredVerdict: 'PHISHING',
            requireConfidence: 0.85
          },
          steps: [
            {
              id: 'step_isolate',
              name: 'Isolate Host IOC',
              actionType: 'ISOLATE_ENDPOINT_IOC',
              parameters: { dropActiveSockets: true }
            },
            {
              id: 'step_case',
              name: 'Dispatch P1 Case',
              actionType: 'CREATE_SOC_CASE',
              parameters: { priority: 'P1' }
            }
          ]
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.name).toBe('Custom Lateral Movement Isolation');
      expect(res.body.data.steps.length).toBe(2);
    });

    it('should trigger and execute a SOAR playbook workflow end-to-end', async () => {
      const res = await request(app)
        .post('/api/playbooks/trigger')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          playbookId: 'pb_zero_day_containment',
          targetUrl: 'https://adversary-c2-harvest.internal/login',
          targetBrand: 'Corporate SSO',
          riskScore: 92,
          verdict: 'PHISHING'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.playbookId).toBe('pb_zero_day_containment');
      expect(res.body.data.status).toBe('SUCCESS');
      expect(res.body.data.steps.length).toBe(4);
      expect(res.body.data.logs.length).toBeGreaterThan(0);
    });

    it('should list historical playbook execution runs', async () => {
      const res = await request(app)
        .get('/api/playbooks/runs')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThan(0);
    });
  });

  describe('Threat Hunting & Deep Forensic Sandbox (/api/hunting)', () => {
    it('should execute multi-vector threat hunt query (Domain Regex)', async () => {
      const res = await request(app)
        .post('/api/hunting/query')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          queryType: 'DOMAIN_REGEX',
          queryValue: '.*phish.*',
          timeRange: 'Last 30 Days'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.query.queryType).toBe('DOMAIN_REGEX');
      expect(res.body.data.totalMatches).toBeGreaterThanOrEqual(1);
      expect(Array.isArray(res.body.data.pivotSuggestions)).toBe(true);
    });

    it('should execute threat hunt query on ASN lookup', async () => {
      const res = await request(app)
        .post('/api/hunting/query')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          queryType: 'ASN_LOOKUP',
          queryValue: 'AS13335',
          timeRange: 'All Time'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.totalMatches).toBeGreaterThanOrEqual(1);
    });

    it('should extract deep forensic sandbox artifact including HAR, TLS chain, and DOM mutations', async () => {
      const res = await request(app)
        .get('/api/hunting/artifact?targetUrl=https://secure-login-attempt.example.com')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.domain).toBe('secure-login-attempt.example.com');
      expect(res.body.data.harArchive.sampleHttpEntries.length).toBeGreaterThan(0);
      expect(res.body.data.tlsCertificateChain.length).toBeGreaterThan(0);
      expect(res.body.data.domMutations.length).toBeGreaterThan(0);
    });
  });

  describe('Threat Intel Platform Connectors (/api/connectors)', () => {
    it('should list all TAXII 2.1, MISP, and AlienVault threat connectors', async () => {
      const res = await request(app)
        .get('/api/connectors')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.length).toBe(4);
    });

    it('should poll and synchronize a specific threat intelligence connector', async () => {
      const res = await request(app)
        .post('/api/connectors/conn_taxii21_cisa/sync')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe('conn_taxii21_cisa');
      expect(res.body.data.totalIocsIngested).toBeGreaterThan(0);
      expect(res.body.data.status).toBe('HEALTHY');
    });

    it('should toggle connector activation state', async () => {
      const res = await request(app)
        .patch('/api/connectors/conn_abuse_ipdb/toggle')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ enabled: true });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.enabled).toBe(true);
    });
  });
});
