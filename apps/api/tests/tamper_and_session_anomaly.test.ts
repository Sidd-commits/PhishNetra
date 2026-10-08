import request from 'supertest';
import { createApp } from '../src/app';

const app = createApp();

describe('Client Tampering, Continuous Session Anomaly & MITRE D3FEND Suite (Milestone 18)', () => {
  describe('Client-Side Anti-Tampering & DOM Cloaking SDK (/api/client-defense)', () => {
    it('should generate client guard script with SRI hash from valid config', async () => {
      const res = await request(app)
        .post('/api/client-defense/generate')
        .send({
          targetDomain: 'login.phishnetra-auth.com',
          enableDevToolsTrap: true,
          enableMutationTrap: true,
          enableClickjackingTrap: true,
          enableWatermarking: true
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.targetDomain).toBe('login.phishnetra-auth.com');
      expect(res.body.data.obfuscatedScript).toContain('PhishNetra Client-Side Anti-Tampering');
      expect(res.body.data.scriptIntegrityHash).toMatch(/^sha256-/);
    });

    it('should reject invalid config with missing targetDomain', async () => {
      const res = await request(app)
        .post('/api/client-defense/generate')
        .send({ targetDomain: '' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should ingest tampering beacon event and log to SOC audit trail', async () => {
      const res = await request(app)
        .post('/api/client-defense/beacon')
        .send({
          targetDomain: 'identity.phishnetra-auth.com',
          tamperType: 'DOM_OVERLAY_INJECTED',
          payloadDetails: {
            unauthorizedInput: 'INPUT#harvest-password',
            actionUrl: 'https://attacker-relay.com/steal'
          },
          severity: 'CRITICAL'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.tamperType).toBe('DOM_OVERLAY_INJECTED');
      expect(res.body.data.severity).toBe('CRITICAL');
    });

    it('should list historical client tampering events', async () => {
      const res = await request(app).get('/api/client-defense/events');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Zero-Trust Continuous Session Verification (/api/session-anomaly)', () => {
    it('should evaluate standard session probe with low risk score and ALLOW action', async () => {
      const res = await request(app)
        .post('/api/session-anomaly/evaluate')
        .send({
          sessionId: 'sess-corp-test-100',
          userEmail: 'bob.engineer@enterprise.com',
          timestamp: new Date().toISOString(),
          ipAddress: '198.51.100.55',
          geoCoordinates: {
            latitude: 37.7749,
            longitude: -122.4194,
            city: 'San Francisco',
            country: 'United States'
          },
          tlsJa3Fingerprint: '771,4865-4866-4867,0-23-65281-10-11,29-23-24,0',
          userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.continuousRiskScore).toBeLessThan(50);
      expect(res.body.data.actionTaken).toBe('ALLOW');
      expect(res.body.data.killSwitchDispatched).toBe(false);
    });

    it('should detect impossible travel and TLS JA3 drift, triggering session TERMINATION', async () => {
      // First probe: Initial legitimate session in London
      const baseTime = Date.now();
      await request(app)
        .post('/api/session-anomaly/evaluate')
        .send({
          sessionId: 'sess-corp-compromised-99',
          userEmail: 'victim@enterprise.com',
          timestamp: new Date(baseTime).toISOString(),
          ipAddress: '51.140.22.10',
          geoCoordinates: {
            latitude: 51.5074,
            longitude: -0.1278,
            city: 'London',
            country: 'United Kingdom'
          },
          tlsJa3Fingerprint: '771,4865-4866-4867,0-23-65281-10-11,29-23-24,0',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120'
        });

      // Second probe: 10 minutes later in Tokyo (speed > 50,000 km/h) with mutated TLS fingerprint
      const res = await request(app)
        .post('/api/session-anomaly/evaluate')
        .send({
          sessionId: 'sess-corp-compromised-99',
          userEmail: 'victim@enterprise.com',
          timestamp: new Date(baseTime + 1000 * 60 * 10).toISOString(),
          ipAddress: '133.242.18.5',
          geoCoordinates: {
            latitude: 35.6762,
            longitude: 139.6503,
            city: 'Tokyo',
            country: 'Japan'
          },
          tlsJa3Fingerprint: '771,49195-49199,43-13,29,0', // Altered signature
          userAgent: 'python-requests/2.31.0' // Mutated client
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.continuousRiskScore).toBeGreaterThanOrEqual(80);
      expect(res.body.data.actionTaken).toBe('TERMINATE_SESSION');
      expect(res.body.data.killSwitchDispatched).toBe(true);
      expect(res.body.data.tlsDriftDetected).toBe(true);
      expect(res.body.data.deviceProfileMutated).toBe(true);
      expect(res.body.data.impossibleTravelVelocityKmh).toBeGreaterThan(1000);
    });

    it('should retrieve session telemetry history', async () => {
      const res = await request(app).get('/api/session-anomaly/history/sess-corp-compromised-99');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('MITRE D3FEND Countermeasure Matrix (/api/d3fend)', () => {
    it('should return complete D3FEND coverage across 5 tactical pillars', async () => {
      const res = await request(app).get('/api/d3fend/matrix');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.totalTechniques).toBeGreaterThanOrEqual(10);
      expect(res.body.data.overallDefensivePostureScore).toBeGreaterThanOrEqual(90);

      // Verify all 5 tactics covered
      expect(res.body.data.tacticCoverage).toHaveProperty('MODEL');
      expect(res.body.data.tacticCoverage).toHaveProperty('HARDEN');
      expect(res.body.data.tacticCoverage).toHaveProperty('DETECT');
      expect(res.body.data.tacticCoverage).toHaveProperty('ISOLATE');
      expect(res.body.data.tacticCoverage).toHaveProperty('DECEIVE');
    });
  });
});
