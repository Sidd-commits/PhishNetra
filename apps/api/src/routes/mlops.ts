import { Router, Request, Response } from 'express';
import { mlopsService } from '../services/MLOpsService';
import { z } from 'zod';

const router = Router();

const ExplainRequestSchema = z.object({
  url: z.string().min(1, 'URL is required')
});

const ActivateRequestSchema = z.object({
  version: z.string().min(1, 'Version is required')
});

const RetrainRequestSchema = z.object({
  dataset_path: z.string().optional(),
  augmented_samples: z.array(z.object({ url: z.string(), label: z.number() })).optional(),
  algorithm: z.string().optional(),
  auto_activate_threshold: z.number().optional(),
  version_tag: z.string().optional()
});

const AdversarialTestSchema = z.object({
  url: z.string().optional(),
  attack_types: z.array(z.string()).optional(),
  custom_urls: z.array(z.string()).optional()
});

/**
 * POST /api/mlops/explain
 * SHAP Feature Attribution & Local Explainability
 */
router.post('/explain', async (req: Request, res: Response, next) => {
  try {
    const { url } = ExplainRequestSchema.parse(req.body);
    const explanation = await mlopsService.explainPrediction(url);
    res.json({
      success: true,
      data: explanation
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/mlops/models
 * List all models in Model Registry
 */
router.get('/models', async (_req: Request, res: Response, next) => {
  try {
    const overview = await mlopsService.getModelRegistry();
    res.json({
      success: true,
      data: overview
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/mlops/models/:version
 * Specific Model Details
 */
router.get('/models/:version', async (req: Request, res: Response, next) => {
  try {
    const model = await mlopsService.getModelDetails(req.params.version);
    res.json({
      success: true,
      data: model
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/mlops/models/activate
 * Hot-swap active inference model
 */
router.post('/models/activate', async (req: Request, res: Response, next) => {
  try {
    const { version } = ActivateRequestSchema.parse(req.body);
    const result = await mlopsService.activateModel(version);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/mlops/drift
 * Drift Metrics (PSI & KS statistics)
 */
router.get('/drift', async (_req: Request, res: Response, next) => {
  try {
    const report = await mlopsService.getDriftMetrics();
    res.json({
      success: true,
      data: report
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/mlops/drift/evaluate
 * Evaluate drift on custom batch of live samples
 */
router.post('/drift/evaluate', async (req: Request, res: Response, next) => {
  try {
    const liveUrls = req.body.live_urls as string[] | undefined;
    const report = await mlopsService.getDriftMetrics(liveUrls);
    res.json({
      success: true,
      data: report
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/mlops/retrain
 * Trigger continuous model retraining pipeline
 */
router.post('/retrain', async (req: Request, res: Response, next) => {
  try {
    const params = RetrainRequestSchema.parse(req.body);
    const result = await mlopsService.triggerRetraining(params);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/mlops/adversarial
 * Run adversarial robustness evaluation suite or test single URL
 */
router.post('/adversarial', async (req: Request, res: Response, next) => {
  try {
    const params = AdversarialTestSchema.parse(req.body);
    const report = await mlopsService.runAdversarialTest(params);
    res.json({
      success: true,
      data: report
    });
  } catch (error) {
    next(error);
  }
});

export default router;
