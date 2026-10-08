import { Router, Request, Response } from 'express';
import { threatHuntingService } from '../services/hunting/ThreatHuntingService';
import { ThreatHuntQuerySchema } from '@phishnetra/shared';
import { requireAuth } from '../middleware/authMiddleware';

const router = Router();

// Execute threat hunting query
router.post('/query', requireAuth, (req: Request, res: Response) => {
  try {
    const parsed = ThreatHuntQuerySchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.issues[0]?.message });
    }
    const result = threatHuntingService.executeHunt(parsed.data);
    res.status(200).json({ success: true, data: result });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get deep forensic artifact for a URL
router.get('/artifact', requireAuth, (req: Request, res: Response) => {
  try {
    const targetUrl = (req.query.targetUrl as string) || 'https://phishing-portal.internal/login';
    const artifact = threatHuntingService.getForensicArtifact(targetUrl);
    res.status(200).json({ success: true, data: artifact });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
