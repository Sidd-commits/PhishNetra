import { Router, Request, Response } from 'express';
import { FAIRRiskParamsSchema } from '@phishnetra/shared';
import { cyberRiskQuantificationService } from '../services/fair/CyberRiskQuantificationService';

export const riskQuantificationRouter = Router();

// GET /api/risk-quantification/defaults
riskQuantificationRouter.get('/defaults', (_req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    data: {
      annualPhishingAttempts: 5000,
      susceptibilityRate: 0.12,
      controlEffectiveness: 0.85,
      averageEmployeeCount: 500,
      costPerCompromisedCredential: 4200,
      secondaryRegulatoryFineLikelihood: 0.15,
      maxRegulatoryFine: 2500000
    }
  });
});

// POST /api/risk-quantification/calculate
riskQuantificationRouter.post('/calculate', (req: Request, res: Response) => {
  try {
    const params = FAIRRiskParamsSchema.parse(req.body);
    const result = cyberRiskQuantificationService.calculateFAIRRisk(params);
    return res.status(200).json({ success: true, data: result });
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: { code: 'INVALID_FAIR_PARAMS', message: error.message }
    });
  }
});
