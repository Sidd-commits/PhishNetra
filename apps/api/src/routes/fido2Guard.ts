import { Router, Request, Response, NextFunction } from 'express';
import { fido2CredentialGuardService } from '../services/fido2/FIDO2CredentialGuardService';
import { FIDO2ProbeRequestSchema } from '@phishnetra/shared';

const router = Router();

// POST /api/fido2-guard/probe
router.post('/probe', (req: Request, res: Response, next: NextFunction) => {
  try {
    const parsed = FIDO2ProbeRequestSchema.parse(req.body);
    const assessment = fido2CredentialGuardService.evaluateTarget(parsed);
    res.json({ success: true, data: assessment });
  } catch (error) {
    next(error);
  }
});

// GET /api/fido2-guard/history
router.get('/history', (req: Request, res: Response) => {
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 20;
  const history = fido2CredentialGuardService.listEvaluations(limit);
  res.json({ success: true, data: history, count: history.length });
});

// GET /api/fido2-guard/:id
router.get('/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const assessment = fido2CredentialGuardService.getEvaluation(id);
  if (!assessment) {
    return res.status(404).json({ success: false, error: `FIDO2 Assessment ${id} not found.` });
  }
  res.json({ success: true, data: assessment });
});

export default router;
