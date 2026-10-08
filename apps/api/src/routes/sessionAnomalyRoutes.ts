import { Router, Request, Response } from 'express';
import { SessionTelemetryProbeSchema } from '@phishnetra/shared';
import { continuousSessionService } from '../services/session/ContinuousSessionService';

export const sessionAnomalyRouter = Router();

// POST /api/session-anomaly/evaluate
sessionAnomalyRouter.post('/evaluate', (req: Request, res: Response) => {
  try {
    const probe = SessionTelemetryProbeSchema.parse(req.body);
    const assessment = continuousSessionService.evaluateSession(probe);
    return res.status(200).json({ success: true, data: assessment });
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: { code: 'INVALID_SESSION_PROBE', message: error.message }
    });
  }
});

// GET /api/session-anomaly/history/:sessionId
sessionAnomalyRouter.get('/history/:sessionId', (req: Request, res: Response) => {
  const history = continuousSessionService.getSessionHistory(req.params.sessionId);
  return res.status(200).json({ success: true, data: history });
});
