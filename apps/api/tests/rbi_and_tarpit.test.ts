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

describe('Remote Browser Isolation (RBI), Tarpit & TAXII 2.1 Server Suite (Milestone 15)', () => {
  const token = generateTestToken();

  describe('Remote Browser Isolation (RBI) Sandbox (/api/rbi)', () => {
    let createdSessionId = '';

    it('should list active and historical RBI sandbox sessions', async () => {
      const res = await request(app)
        .get('/api/rbi/sessions')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
      expect(res.body.data[0]).toHaveProperty('deWeaponizedHtml');
      expect(res.body.data[0]).toHaveProperty('securityPolicy');
    });

    it('should create an isolated virtual browser container session', async () => {
      const res = await request(app)
        .post('/api/rbi/sessions')
        .set('Authorization', `Bearer ${token}`)
        .send({
          targetUrl: 'https://paypal-security-auth-update.com/verify',
          securityPolicy: {
            blockFormSubmit: true,
            blockWebSockets: true,
            canvasRandomization: true
          }
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data.status).toBe('RUNNING');
      expect(res.body.data.domain).toBe('paypal-security-auth-update.com');
      expect(Array.isArray(res.body.data.liveEvents)).toBe(true);
      createdSessionId = res.body.data.id;
    });

    it('should retrieve single RBI session details', async () => {
      const res = await request(app)
        .get(`/api/rbi/sessions/${createdSessionId}`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe(createdSessionId);
    });

    it('should terminate an active RBI session', async () => {
      const res = await request(app)
        .post(`/api/rbi/sessions/${createdSessionId}/terminate`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('TERMINATED');
    });
  });

  describe('Phishing Tarpit & Credential Poisoner (/api/tarpit)', () => {
    let createdTaskId = '';

    it('should list all active and historical tarpit flooding tasks', async () => {
      const res = await request(app)
        .get('/api/tarpit/tasks')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    });

    it('should launch a new synthetic credential tarpit flooder task', async () => {
      const res = await request(app)
        .post('/api/tarpit/tasks')
        .set('Authorization', `Bearer ${token}`)
        .send({
          targetUrl: 'https://paypal-security-auth-update.com/login.php',
          targetFormAction: 'https://paypal-security-auth-update.com/drop.php',
          concurrency: 6,
          credentialsCount: 25,
          targetBrand: 'PayPal'
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data.status).toBe('ACTIVE');
      expect(res.body.data.totalCredentialsInjected).toBe(25);
      expect(Array.isArray(res.body.data.poisonedCredentials)).toBe(true);
      expect(res.body.data.poisonedCredentials.length).toBe(25);
      expect(res.body.data.poisonedCredentials[0]).toHaveProperty('canaryTag');
      createdTaskId = res.body.data.id;
    });

    it('should retrieve single tarpit task telemetry', async () => {
      const res = await request(app)
        .get(`/api/tarpit/tasks/${createdTaskId}`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe(createdTaskId);
    });

    it('should stop an active tarpit task', async () => {
      const res = await request(app)
        .post(`/api/tarpit/tasks/${createdTaskId}/stop`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('STOPPED');
    });
  });

  describe('TAXII 2.1 & STIX 2.1 Server (/api/taxii21)', () => {
    it('should return TAXII 2.1 Discovery document', async () => {
      const res = await request(app)
        .get('/api/taxii21/discovery');

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('title');
      expect(res.body).toHaveProperty('defaultApiRoot');
      expect(Array.isArray(res.body.apiRoots)).toBe(true);
    });

    it('should list TAXII 2.1 Collections', async () => {
      const res = await request(app)
        .get('/api/taxii21/collections');

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('collections');
      expect(Array.isArray(res.body.collections)).toBe(true);
      expect(res.body.collections.length).toBeGreaterThanOrEqual(3);
    });

    it('should get collection details and STIX 2.1 objects', async () => {
      const colRes = await request(app)
        .get('/api/taxii21/collections/col-verified-phishing');

      expect(colRes.status).toBe(200);
      expect(colRes.body.id).toBe('col-verified-phishing');
      expect(colRes.body.canRead).toBe(true);

      const objRes = await request(app)
        .get('/api/taxii21/collections/col-verified-phishing/objects');

      expect(objRes.status).toBe(200);
      expect(objRes.body.type).toBe('bundle');
      expect(Array.isArray(objRes.body.objects)).toBe(true);
      expect(objRes.body.objects.length).toBeGreaterThanOrEqual(1);
    });
  });
});
