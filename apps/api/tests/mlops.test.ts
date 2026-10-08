import request from 'supertest';
import { createApp } from '../src/app';

const app = createApp();

jest.setTimeout(30000);

describe('MLOps & Model Lifecycle API Test Suite (Milestone 7)', () => {
  it('POST /api/mlops/explain should compute SHAP feature attribution and narrative', async () => {
    const res = await request(app)
      .post('/api/mlops/explain')
      .send({ url: 'http://192.168.1.1/login-account-update.php' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toBeDefined();
    expect(res.body.data.url).toBe('http://192.168.1.1/login-account-update.php');
    expect(res.body.data.attributions).toBeInstanceOf(Array);
    expect(res.body.data.attributions.length).toBeGreaterThan(0);
    expect(typeof res.body.data.narrativeSummary).toBe('string');
    expect(res.body.data.topPhishingFactors).toBeInstanceOf(Array);
  });

  it('GET /api/mlops/models should list registered models and active model', async () => {
    const res = await request(app)
      .get('/api/mlops/models');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.registeredModels).toBeInstanceOf(Array);
    expect(res.body.data.totalModels).toBeGreaterThanOrEqual(1);
    expect(res.body.data.activeModel).toBeDefined();
  });

  it('GET /api/mlops/drift should return PSI and KS distribution metrics', async () => {
    const res = await request(app)
      .get('/api/mlops/drift');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.overallDriftStatus).toMatch(/STABLE|MODERATE|CRITICAL/);
    expect(res.body.data.features).toBeInstanceOf(Array);
    expect(res.body.data.features.length).toBeGreaterThan(0);
    expect(typeof res.body.data.recommendation).toBe('string');
  });

  it('POST /api/mlops/adversarial should run adversarial robustness evaluation', async () => {
    const res = await request(app)
      .post('/api/mlops/adversarial')
      .send({
        url: 'http://192.168.1.100/admin-login.php',
        attack_types: ['HOMOGLYPH', 'KEYWORD_STUFFING', 'LENGTH_INFLATION']
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.totalTests).toBe(3);
    expect(res.body.data.results).toHaveLength(3);
    expect(typeof res.body.data.overallRobustnessScore).toBe('number');
  });
});
