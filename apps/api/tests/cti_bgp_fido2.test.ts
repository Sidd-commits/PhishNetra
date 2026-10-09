import request from 'supertest';
import { createApp } from '../src/app';

const app = createApp();

describe('Milestone 20: CTI TAXII Exchange, BGP Route Integrity & FIDO2 Guard Suite', () => {
  describe('Decentralized CTI TAXII 2.1 Threat Exchange (/api/cti-exchange)', () => {
    it('should list all registered TAXII 2.1 CTI feeds', async () => {
      const res = await request(app).get('/api/cti-exchange/feeds');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(3);
      expect(res.body.data.some((f: any) => f.id === 'feed-cisa-ais')).toBe(true);
    });

    it('should register a new custom TAXII feed', async () => {
      const res = await request(app)
        .post('/api/cti-exchange/feeds')
        .send({
          name: 'Internal Banking ISAC TAXII Feed',
          description: 'Private financial sector threat intelligence stream',
          apiRootUrl: 'https://taxii.internal-bank.org/api21/',
          collectionId: 'col-swift-phishing',
          authType: 'API_KEY',
          apiKey: 'secret-banking-key-123',
          tlpMarking: 'TLP:AMBER',
          syncIntervalMinutes: 15,
          isActive: true,
          autoBlockIndicators: true
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.name).toBe('Internal Banking ISAC TAXII Feed');
      expect(res.body.data.id).toMatch(/^feed-/);
    });

    it('should trigger on-demand sync for a TAXII feed and ingest STIX 2.1 indicators', async () => {
      const res = await request(app).post('/api/cti-exchange/feeds/feed-cisa-ais/sync');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('SUCCESS');
      expect(res.body.data.indicatorsIngested).toBeGreaterThan(0);
      expect(Array.isArray(res.body.data.sampleIndicators)).toBe(true);
    });

    it('should list ingested indicators with filtering', async () => {
      const res = await request(app)
        .get('/api/cti-exchange/indicators')
        .query({ indicatorType: 'URL' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      if (res.body.data.length > 0) {
        expect(res.body.data[0].indicatorType).toBe('URL');
      }
    });

    it('should retrieve overall CTI exchange telemetry and statistics', async () => {
      const res = await request(app).get('/api/cti-exchange/stats');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.totalFeeds).toBeGreaterThanOrEqual(3);
      expect(res.body.data.totalIndicators).toBeGreaterThan(0);
      expect(res.body.data.indicatorsByType).toBeDefined();
    });
  });

  describe('Infrastructure Integrity Radar: BGP Route & DNS Poisoning (/api/bgp-integrity)', () => {
    it('should verify clean infrastructure routing for legitimate domain', async () => {
      const res = await request(app)
        .post('/api/bgp-integrity/probe')
        .send({
          target: 'microsoft.com',
          expectedAsn: 8075
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.rpkiStatus).toBe('VALID');
      expect(res.body.data.isHijackSuspicious).toBe(false);
      expect(res.body.data.dnsPoisoningDetected).toBe(false);
      expect(res.body.data.routeResolutionIntegrityScore).toBeGreaterThanOrEqual(90);
      expect(res.body.data.alertSeverity).toBe('CLEAN');
    });

    it('should detect simulated BGP prefix hijack and return CRITICAL severity', async () => {
      const res = await request(app)
        .post('/api/bgp-integrity/probe')
        .send({
          target: 'hijack-simulation-bank.com'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.rpkiStatus).toBe('INVALID');
      expect(res.body.data.isHijackSuspicious).toBe(true);
      expect(res.body.data.asPathAnomalyDetected).toBe(true);
      expect(res.body.data.alertSeverity).toBe('CRITICAL');
      expect(res.body.data.forensicSummary).toContain('BGP HIJACK ALERT');
    });

    it('should detect simulated DNS cache poisoning with divergent answers', async () => {
      const res = await request(app)
        .post('/api/bgp-integrity/probe')
        .send({
          target: 'poisoned-dns-portal.org'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.dnsPoisoningDetected).toBe(true);
      expect(res.body.data.dnssecStatus).toBe('BOGUS');
      expect(res.body.data.alertSeverity).toBe('CRITICAL');
      expect(res.body.data.resolverResponses.some((r: any) => r.divergentFromConsensus)).toBe(true);
    });

    it('should retrieve BGP assessment history', async () => {
      const res = await request(app).get('/api/bgp-integrity/history');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThan(0);
    });
  });

  describe('FIDO2 / WebAuthn Phishing-Resistant MFA Guard (/api/fido2-guard)', () => {
    it('should verify Passkey cryptographic immunity against AiTM proxy', async () => {
      const res = await request(app)
        .post('/api/fido2-guard/probe')
        .send({
          targetUrl: 'https://login.microsoft.com-evilginx-proxy.net/auth',
          claimedBrand: 'microsoft',
          authProtocol: 'WEBAUTHN_FIDO2'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.originBindingMismatch).toBe(true);
      expect(res.body.data.passkeyImmunityConfirmed).toBe(true);
      expect(res.body.data.mfaStrengthTier).toBe('PHISHING_RESISTANT_FIDO2');
      expect(res.body.data.mitmProxyVulnerabilityScore).toBe(0);
      expect(res.body.data.proxyEvasionDetected).toBe(true);
      expect(res.body.data.webauthnPolicyEnforcementSnippet).toContain('relyingParty');
    });

    it('should flag vulnerable legacy SMS authentication as high MitM risk', async () => {
      const res = await request(app)
        .post('/api/fido2-guard/probe')
        .send({
          targetUrl: 'https://login.microsoft.com-evilginx-proxy.net/auth',
          claimedBrand: 'microsoft',
          authProtocol: 'SMS_OTP'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.mfaStrengthTier).toBe('VULNERABLE_LEGACY_SMS');
      expect(res.body.data.mitmProxyVulnerabilityScore).toBe(95);
    });

    it('should retrieve FIDO2 assessment history', async () => {
      const res = await request(app).get('/api/fido2-guard/history');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThan(0);
    });
  });
});
