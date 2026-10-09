import { Router, Request, Response, NextFunction } from 'express';
import { bgpRouteIntegrityService } from '../services/integrity/BGPRouteIntegrityService';
import { BGPProbeRequestSchema } from '@phishnetra/shared';

const router = Router();

// POST /api/bgp-integrity/probe
router.post('/probe', (req: Request, res: Response, next: NextFunction) => {
  try {
    const parsed = BGPProbeRequestSchema.parse(req.body);
    const assessment = bgpRouteIntegrityService.evaluateTarget(parsed);
    res.json({ success: true, data: assessment });
  } catch (error) {
    next(error);
  }
});

// GET /api/bgp-integrity/history
router.get('/history', (req: Request, res: Response) => {
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 20;
  const history = bgpRouteIntegrityService.listAssessments(limit);
  res.json({ success: true, data: history, count: history.length });
});

// GET /api/bgp-integrity/:id
router.get('/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const assessment = bgpRouteIntegrityService.getAssessment(id);
  if (!assessment) {
    return res.status(404).json({ success: false, error: `BGP Assessment ${id} not found.` });
  }
  res.json({ success: true, data: assessment });
});

export default router;
