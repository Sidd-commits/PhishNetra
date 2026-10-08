import { Router, Request, Response } from 'express';
import { TelecomThreatProbeSchema } from '@phishnetra/shared';
import { telecomThreatFusionService } from '../services/telecom/TelecomThreatFusionService';

export const telecomThreatRouter = Router();

telecomThreatRouter.post('/assess', (req: Request, res: Response) => {
  try {
    const parseResult = TelecomThreatProbeSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid Telecom Threat Probe payload',
        details: parseResult.error.format()
      });
    }

    const assessment = telecomThreatFusionService.assessThreat(parseResult.data);
    return res.status(200).json({
      success: true,
      data: assessment
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: 'Telecom threat assessment failed',
      details: err.message
    });
  }
});

telecomThreatRouter.get('/history', (_req: Request, res: Response) => {
  try {
    const history = telecomThreatFusionService.getHistory();
    return res.status(200).json({
      success: true,
      data: history
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: 'Failed to retrieve telecom assessment history',
      details: err.message
    });
  }
});
