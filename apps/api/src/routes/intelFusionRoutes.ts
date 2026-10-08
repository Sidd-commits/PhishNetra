import { Router, Request, Response } from 'express';
import { ThreatFusionScoreRequestSchema, BayesianDecayConfigSchema } from '@phishnetra/shared';
import { ThreatFusionService } from '../services/intel/ThreatFusionService';

export const intelFusionRouter = Router();

// GET /api/intel-fusion — List all multi-source fused IOC entries with live decayed scores
intelFusionRouter.get('/', async (_req: Request, res: Response) => {
  try {
    const entries = ThreatFusionService.listEntries();
    return res.json({
      success: true,
      data: entries
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: err.message || 'Failed to list fused IOC entries'
      }
    });
  }
});

// POST /api/intel-fusion/score — Score or ingest an IOC with Bayesian decay
intelFusionRouter.post('/score', async (req: Request, res: Response) => {
  try {
    const parseResult = ThreatFusionScoreRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid IOC score request',
          details: parseResult.error.format()
        }
      });
    }

    const result = ThreatFusionService.evaluateIOC(parseResult.data);
    return res.json({
      success: true,
      data: result
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: err.message || 'Failed to score fused IOC'
      }
    });
  }
});

// GET /api/intel-fusion/config — Get Bayesian decay configuration
intelFusionRouter.get('/config', async (_req: Request, res: Response) => {
  try {
    const config = ThreatFusionService.getDecayConfig();
    return res.json({
      success: true,
      data: config
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: err.message || 'Failed to get Bayesian decay config'
      }
    });
  }
});

// PATCH /api/intel-fusion/config — Update Bayesian decay configuration
intelFusionRouter.patch('/config', async (req: Request, res: Response) => {
  try {
    const parseResult = BayesianDecayConfigSchema.partial().safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid decay config update',
          details: parseResult.error.format()
        }
      });
    }

    const updated = ThreatFusionService.updateDecayConfig(parseResult.data);
    return res.json({
      success: true,
      data: updated
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: err.message || 'Failed to update Bayesian decay config'
      }
    });
  }
});
