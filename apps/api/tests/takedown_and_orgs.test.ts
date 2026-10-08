import request from 'supertest';
import { createApp } from '../src/app';
import { authService } from '../src/services/AuthService';

describe('Takedown Engine, Team Workspaces & Executive Intelligence Suite (Milestone 12)', () => {
  const app = createApp();
  let authToken: string;

  beforeAll(async () => {
    const res = await authService.register({
      email: `takedown_tester_${Date.now()}@phishnetra.test`,
      password: 'ComplexP@ssw0rd!123',
      name: 'Takedown Officer'
    });
    authToken = res.token;
  });

  describe('Takedown Notice & RFC 2142 Abuse Engine (/api/takedowns)', () => {
    let createdNoticeId: string;

    it('should list all initial seeded takedown notices', async () => {
      const res = await request(app)
        .get('/api/takedowns')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(2);
    });

    it('should create a formal RFC 2142 abuse notice targeting a malicious domain', async () => {
      const res = await request(app)
        .post('/api/takedowns')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          targetUrl: 'https://login-verify-account.bank-security-portal.internal/auth',
          targetBrand: 'Major Bank Corp',
          noticeType: 'RFC2142_ABUSE_NOTICE',
          customNotes: 'Observed 120 credential harvest attempts in 10 minutes.'
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.targetDomain).toBe('login-verify-account.bank-security-portal.internal');
      expect(res.body.data.status).toBe('DRAFTED');
      expect(res.body.data.trackingNumber).toMatch(/^TKD-MAJO-\d+$/);
      expect(res.body.data.bodyText).toContain('RFC 2142 Abuse Mailbox');
      createdNoticeId = res.body.data.id;
    });

    it('should update the status of an existing notice to DISPATCHED', async () => {
      const res = await request(app)
        .patch(`/api/takedowns/${createdNoticeId}/status`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ status: 'DISPATCHED' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('DISPATCHED');
      expect(res.body.data.dispatchedAt).toBeDefined();
    });

    it('should fetch a single takedown notice by ID', async () => {
      const res = await request(app)
        .get(`/api/takedowns/${createdNoticeId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe(createdNoticeId);
    });
  });

  describe('Organization & Team Workspace Hub (/api/organizations)', () => {
    let invitedMemberId: string;

    it('should retrieve workspace metadata and security policies', async () => {
      const res = await request(app)
        .get('/api/organizations/workspace')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.name).toBe('Apex Global Security Operations Center');
      expect(res.body.data.plan).toBe('ENTERPRISE_SOC');
      expect(res.body.data.members.length).toBeGreaterThanOrEqual(4);
    });

    it('should update workspace security policy', async () => {
      const res = await request(app)
        .patch('/api/organizations/policy')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          mfaEnforced: true,
          autoSinkholingEnabled: true,
          retentionDays: 180
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.securityPolicy.retentionDays).toBe(180);
    });

    it('should invite a new SOC Analyst team member', async () => {
      const res = await request(app)
        .post('/api/organizations/members')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          name: 'Nakamoto Satoshi',
          email: 'satoshi@apex-security.internal',
          role: 'SOC_ANALYST'
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.name).toBe('Nakamoto Satoshi');
      invitedMemberId = res.body.data.id;
    });

    it('should remove the team member from workspace', async () => {
      const res = await request(app)
        .delete(`/api/organizations/members/${invitedMemberId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  describe('Autonomous Executive Threat Intelligence Dossiers (/api/reports/executive)', () => {
    it('should generate an executive threat briefing JSON report', async () => {
      const res = await request(app)
        .get('/api/reports/executive?timeRange=Last+30+Days')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.metrics.totalScans).toBeGreaterThan(0);
      expect(res.body.data.topTargetedBrands.length).toBeGreaterThanOrEqual(3);
      expect(res.body.data.criticalCampaigns.length).toBeGreaterThanOrEqual(2);
      expect(res.body.data.strategicRecommendations.length).toBeGreaterThanOrEqual(3);
    });

    it('should export executive threat report as downloadable Markdown dossier', async () => {
      const res = await request(app)
        .get('/api/reports/executive/download/markdown')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/markdown');
      expect(res.text).toContain('# PhishNetra — Executive Threat Intelligence Dossier');
      expect(res.text).toContain('Top Targeted Brands Distribution');
      expect(res.text).toContain('Active Threat Campaign Rings');
    });
  });
});
