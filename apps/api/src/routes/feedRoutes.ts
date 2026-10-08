import { Router, Request, Response } from 'express';
import { feedSyncService } from '../services/feeds/FeedSyncService';
import { ThreatFeedSource } from '@phishnetra/shared';

const router = Router();

// GET /api/feeds - List all configured threat feeds and sync status
router.get('/', (req: Request, res: Response) => {
  try {
    const feeds = feedSyncService.listFeeds();
    return res.status(200).json({
      success: true,
      data: feeds
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to list threat feeds' }
    });
  }
});

// POST /api/feeds/:source/sync - Trigger sync for specific feed
router.post('/:source/sync', async (req: Request, res: Response) => {
  try {
    const { source } = req.params;
    const actor = (req as any).user?.email || 'admin@phishnetra.internal';
    const result = await feedSyncService.syncFeed(source.toUpperCase() as ThreatFeedSource, actor);

    return res.status(200).json({
      success: true,
      data: result
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to sync threat feed' }
    });
  }
});

// POST /api/feeds/sync-all - Trigger sync for all enabled threat feeds
router.post('/sync-all', async (req: Request, res: Response) => {
  try {
    const actor = (req as any).user?.email || 'admin@phishnetra.internal';
    const results = await feedSyncService.syncAll(actor);

    return res.status(200).json({
      success: true,
      data: results
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to sync all threat feeds' }
    });
  }
});

// PATCH /api/feeds/:source/toggle - Enable or disable a threat feed
router.patch('/:source/toggle', (req: Request, res: Response) => {
  try {
    const { source } = req.params;
    const { enabled } = req.body;

    if (typeof enabled !== 'boolean') {
      return res.status(400).json({
        success: false,
        error: { message: 'Property "enabled" (boolean) is required in request body' }
      });
    }

    const updated = feedSyncService.toggleFeed(source.toUpperCase() as ThreatFeedSource, enabled);
    if (!updated) {
      return res.status(404).json({
        success: false,
        error: { message: `Threat feed source ${source} not found` }
      });
    }

    return res.status(200).json({
      success: true,
      data: updated
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to toggle threat feed status' }
    });
  }
});

export default router;
