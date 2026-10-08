import { Router, Request, Response } from 'express';
import { metricsService } from '../services/metrics/PrometheusMetricsService';

const router = Router();

router.get('/', async (req: Request, res: Response) => {
  try {
    const metrics = await metricsService.generatePrometheusMetrics();
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.status(200).send(metrics);
  } catch (err: any) {
    res.status(500).send(`# ERROR: Failed to generate metrics: ${err.message}\n`);
  }
});

export default router;
