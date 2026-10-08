import { Router, Request, Response } from 'express';
import { threatConnectorHub } from '../services/connectors/ThreatConnectorHub';
import { requireAuth } from '../middleware/authMiddleware';

const router = Router();

// List all threat intelligence platform connectors
router.get('/', requireAuth, (req: Request, res: Response) => {
  try {
    const connectors = threatConnectorHub.listConnectors();
    res.status(200).json({ success: true, data: connectors });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get single connector
router.get('/:id', requireAuth, (req: Request, res: Response) => {
  try {
    const connector = threatConnectorHub.getConnector(req.params.id);
    if (!connector) {
      return res.status(404).json({ success: false, error: 'Connector not found' });
    }
    res.status(200).json({ success: true, data: connector });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Sync single connector
router.post('/:id/sync', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user?.name || 'admin';
    const synced = await threatConnectorHub.syncConnector(req.params.id, user);
    res.status(200).json({ success: true, data: synced });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Sync all enabled connectors
router.post('/sync-all', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = (req as any).user?.name || 'admin';
    const results = await threatConnectorHub.syncAllConnectors(user);
    res.status(200).json({ success: true, data: results });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Toggle connector enabled status
router.patch('/:id/toggle', requireAuth, (req: Request, res: Response) => {
  try {
    const { enabled } = req.body;
    const user = (req as any).user?.name || 'admin';
    const updated = threatConnectorHub.toggleConnector(req.params.id, Boolean(enabled), user);
    res.status(200).json({ success: true, data: updated });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
