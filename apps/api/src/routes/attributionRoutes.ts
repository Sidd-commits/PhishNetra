import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { threatActorAttributionService } from '../services/attribution/ThreatActorAttributionService';

export const attributionRouter = Router();

const MatchRequestSchema = z.object({
  targetDomain: z.string().min(2),
  ttps: z.array(z.string()).optional(),
  asn: z.string().optional()
});

// GET /api/attribution/actors
attributionRouter.get('/actors', (_req: Request, res: Response) => {
  const actors = threatActorAttributionService.listThreatActors();
  return res.status(200).json({ success: true, data: actors });
});

// GET /api/attribution/actors/:id
attributionRouter.get('/actors/:id', (req: Request, res: Response) => {
  const actor = threatActorAttributionService.getThreatActor(req.params.id);
  if (!actor) {
    return res.status(404).json({
      success: false,
      error: { code: 'ACTOR_NOT_FOUND', message: `Threat actor '${req.params.id}' not found.` }
    });
  }
  return res.status(200).json({ success: true, data: actor });
});

// POST /api/attribution/match
attributionRouter.post('/match', (req: Request, res: Response) => {
  try {
    const parsed = MatchRequestSchema.parse(req.body);
    const result = threatActorAttributionService.matchThreatActor(parsed);
    return res.status(200).json({ success: true, data: result });
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: { code: 'INVALID_ATTRIBUTION_REQUEST', message: error.message }
    });
  }
});
