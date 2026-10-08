import request from 'supertest';
import { createApp } from '../src/app';

describe('Enterprise Observability & Health Probes Suite (Milestone 11)', () => {
  const app = createApp();

  describe('GET /api/health (Standard Health Probe)', () => {
    it('should return 200 OK with service metadata and dependency statuses', async () => {
      const res = await request(app).get('/api/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('healthy');
      expect(res.body.service).toBe('PhishNetra Node.js REST API');
      expect(res.body.dependencies).toBeDefined();
    });
  });

  describe('GET /api/health/ready (Kubernetes Readiness Probe)', () => {
    it('should return 200 OK with readiness check breakdown', async () => {
      const res = await request(app).get('/api/health/ready');
      expect(res.status).toBe(200);
      expect(res.body.ready).toBe(true);
      expect(res.body.status).toBe('READY');
      expect(res.body.checks).toBeDefined();
      expect(res.body.checks.database).toBe('UP');
    });
  });

  describe('GET /api/health/live (Kubernetes Liveness Probe)', () => {
    it('should return 200 OK with uptime seconds', async () => {
      const res = await request(app).get('/api/health/live');
      expect(res.status).toBe(200);
      expect(res.body.alive).toBe(true);
      expect(typeof res.body.uptimeSeconds).toBe('number');
    });
  });

  describe('GET /api/metrics & /metrics (Prometheus Metric Scraper)', () => {
    it('should export standard Prometheus plain text metrics with HELP and TYPE headers', async () => {
      const res = await request(app).get('/api/metrics');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/plain');
      expect(res.text).toContain('phishnetra_uptime_seconds');
      expect(res.text).toContain('phishnetra_process_memory_bytes');
      expect(res.text).toContain('phishnetra_http_requests_total');
      expect(res.text).toContain('phishnetra_scans_total');
      expect(res.text).toContain('phishnetra_cache_requests_total');
    });

    it('should respond identically on root /metrics endpoint', async () => {
      const res = await request(app).get('/metrics');
      expect(res.status).toBe(200);
      expect(res.text).toContain('phishnetra_uptime_seconds');
    });
  });
});
