import request from 'supertest';
import { createApp } from '../src/app';

const app = createApp();

jest.setTimeout(30000);

describe('Enterprise SIEM, Webhooks, Case Management & Email Ingestion Suite (Milestone 8)', () => {
  describe('SIEM / SOAR Multi-Format Exporter', () => {
    it('should export threat intelligence in CEF format', async () => {
      const res = await request(app)
        .post('/api/siem/export')
        .send({ format: 'CEF' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.format).toBe('CEF');
      expect(res.body.data.contentType).toContain('text/plain');
      expect(typeof res.body.data.formattedOutput).toBe('string');
    });

    it('should export threat intelligence in LEEF and SENTINEL_JSON formats', async () => {
      const leefRes = await request(app)
        .post('/api/siem/export')
        .send({ format: 'LEEF' });

      expect(leefRes.status).toBe(200);
      expect(leefRes.body.data.format).toBe('LEEF');

      const sentinelRes = await request(app)
        .post('/api/siem/export')
        .send({ format: 'SENTINEL_JSON' });

      expect(sentinelRes.status).toBe(200);
      expect(sentinelRes.body.data.format).toBe('SENTINEL_JSON');
      expect(sentinelRes.body.data.contentType).toBe('application/json');
    });

    it('should serve live stream feed on GET /api/siem/feed', async () => {
      const res = await request(app)
        .get('/api/siem/feed?format=CEF');

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/plain');
    });
  });

  describe('Webhook & Alert Notification Channels', () => {
    let createdWebhookId: string;

    it('should list configured webhooks', async () => {
      const res = await request(app).get('/api/notifications/webhooks');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeInstanceOf(Array);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    });

    it('should create and test a new webhook channel', async () => {
      const createRes = await request(app)
        .post('/api/notifications/webhooks')
        .send({
          name: 'Security Ops Discord Bot',
          url: 'https://notifications.phishnetra.internal/discord/mock_channel',
          channelType: 'DISCORD',
          minSeverity: 'HIGH'
        });

      expect(createRes.status).toBe(201);
      expect(createRes.body.data.id).toBeDefined();
      createdWebhookId = createRes.body.data.id;

      const testRes = await request(app)
        .post(`/api/notifications/webhooks/${createdWebhookId}/test`);

      expect(testRes.status).toBe(200);
      expect(testRes.body.data.success).toBe(true);
    });

    it('should retrieve delivery logs', async () => {
      const res = await request(app).get('/api/notifications/logs');
      expect(res.status).toBe(200);
      expect(res.body.data).toBeInstanceOf(Array);
    });
  });

  describe('SOC Analyst Case Management & Remediation', () => {
    let caseId: string;

    it('should list open cases', async () => {
      const res = await request(app).get('/api/cases');
      expect(res.status).toBe(200);
      expect(res.body.data).toBeInstanceOf(Array);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    });

    it('should create a new SOC case, add notes, and generate remediation artifacts', async () => {
      const createRes = await request(app)
        .post('/api/cases')
        .send({
          title: 'Suspicious Microsoft SSO Credential Harvester',
          description: 'Multi-layer engine identified active credential harvesting targeting Microsoft corporate users.',
          severity: 'CRITICAL',
          targetUrl: 'http://192.168.1.50/login.php',
          targetDomain: 'login.microsoftonline.update-portal.xyz',
          assignedAnalyst: 'Lead SOC Investigator'
        });

      expect(createRes.status).toBe(201);
      caseId = createRes.body.data.id;
      expect(createRes.body.data.status).toBe('OPEN');

      // Add Note
      const noteRes = await request(app)
        .post(`/api/cases/${caseId}/notes`)
        .send({
          author: 'Lead SOC Investigator',
          text: 'Verified malicious form action posting credentials cross-origin.'
        });

      expect(noteRes.status).toBe(200);
      expect(noteRes.body.data.notes.length).toBe(1);

      // Generate DNS Sinkhole Remediation
      const remRes = await request(app)
        .post(`/api/cases/${caseId}/remediate`)
        .send({ actionType: 'DNS_SINKHOLE' });

      expect(remRes.status).toBe(200);
      expect(remRes.body.data.actionType).toBe('DNS_SINKHOLE');
      expect(remRes.body.data.generatedArtifact).toContain('CNAME sinkhole.phishnetra.internal.');
    });

    it('should update case lifecycle status to RESOLVED', async () => {
      const res = await request(app)
        .patch(`/api/cases/${caseId}`)
        .send({ status: 'RESOLVED', note: 'Threat neutralized via DNS sinkhole.' });

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe('RESOLVED');
      expect(res.body.data.closedAt).toBeDefined();
    });
  });

  describe('Email & Raw IOC Ingestion Engine', () => {
    it('should extract defanged and obfuscated IOCs from unstructured text', async () => {
      const rawReport = `
        Incident Report: Attackers deployed hxxp://evil-payload[.]xyz/auth/login.php
        Command & Control server: 198.51.100.25
        Malware payload SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        Phishing contact: attacker@phish-domain.top
      `;

      const res = await request(app)
        .post('/api/ingest/raw-ioc')
        .send({ rawText: rawReport });

      expect(res.status).toBe(200);
      expect(res.body.data.urls).toContain('http://evil-payload.xyz/auth/login.php');
      expect(res.body.data.ips).toContain('198.51.100.25');
      expect(res.body.data.emails).toContain('attacker@phish-domain.top');
      expect(res.body.data.hashes.length).toBeGreaterThan(0);
    });

    it('should parse raw EML email, detect spoofing, and compute composite phishing score', async () => {
      const rawEml = `
From: security@chase.com
Return-Path: spoofed@attacker-server.xyz
Reply-To: phisher@rogue-inbox.com
Subject: URGENT: Your Account Has Been Suspended
Date: Thu, 08 Oct 2026 10:00:00 GMT
Authentication-Results: spf=fail; dmarc=fail; dkim=none

Dear Customer,
Please verify your banking credentials immediately at:
http://192.168.1.1/login.php?token=928402
      `;

      const res = await request(app)
        .post('/api/ingest/email')
        .send({ rawEmlText: rawEml, evaluateExtractedUrls: true });

      expect(res.status).toBe(200);
      expect(res.body.data.headers.isSpoofed).toBe(true);
      expect(res.body.data.headers.spfStatus).toBe('FAIL');
      expect(res.body.data.headers.dmarcStatus).toBe('FAIL');
      expect(res.body.data.totalUrlsExtracted).toBe(1);
      expect(res.body.data.phishingScore).toBeGreaterThanOrEqual(50);
      expect(res.body.data.verdict).toMatch(/PHISHING|SUSPICIOUS/);
    });
  });
});
