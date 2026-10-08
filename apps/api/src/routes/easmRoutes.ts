import { Router, Request, Response } from 'express';
import { requireAuth } from '../middleware/authMiddleware';
import { CreateAttackSurfaceAssetRequestSchema } from '@phishnetra/shared';
import { attackSurfaceService } from '../services/easm/AttackSurfaceService';

const router = Router();

// GET /api/attack-surface/assets - List all monitored perimeter assets
router.get('/assets', requireAuth, (req: Request, res: Response) => {
  try {
    const assets = attackSurfaceService.listAssets();
    return res.json({ success: true, count: assets.length, data: assets });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to list attack surface assets', details: err.message });
  }
});

// POST /api/attack-surface/assets - Add new perimeter asset
router.post('/assets', requireAuth, (req: Request, res: Response) => {
  try {
    const parseResult = CreateAttackSurfaceAssetRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: 'Invalid asset creation payload', details: parseResult.error.format() });
    }

    const actor = {
      id: req.user?.userId || 'usr-analyst-1',
      name: req.user?.email ? req.user.email.split('@')[0] : 'SOC Analyst'
    };

    const asset = attackSurfaceService.createAsset(parseResult.data, actor);
    return res.status(201).json({ success: true, data: asset });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to add attack surface asset', details: err.message });
  }
});

// DELETE /api/attack-surface/assets/:id - Remove perimeter asset
router.delete('/assets/:id', requireAuth, (req: Request, res: Response) => {
  try {
    const actor = {
      id: req.user?.userId || 'usr-analyst-1',
      name: req.user?.email ? req.user.email.split('@')[0] : 'SOC Analyst'
    };

    const removed = attackSurfaceService.removeAsset(req.params.id, actor);
    if (!removed) {
      return res.status(404).json({ error: 'Attack surface asset not found' });
    }
    return res.json({ success: true, message: 'Asset removed successfully' });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to remove attack surface asset', details: err.message });
  }
});

// GET /api/attack-surface/ct-logs - Stream Certificate Transparency entries
router.get('/ct-logs', requireAuth, (req: Request, res: Response) => {
  try {
    const logs = attackSurfaceService.listCTLogs();
    return res.json({ success: true, count: logs.length, data: logs });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to list CT logs', details: err.message });
  }
});

// POST /api/attack-surface/scan - Trigger live perimeter sweep
router.post('/scan', requireAuth, (req: Request, res: Response) => {
  try {
    const scanResult = attackSurfaceService.triggerPerimeterScan();
    return res.json({ success: true, data: scanResult });
  } catch (err: any) {
    return res.status(500).json({ error: 'Perimeter scan failed', details: err.message });
  }
});

export default router;
