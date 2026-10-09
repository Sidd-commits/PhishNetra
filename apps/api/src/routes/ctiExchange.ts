import { Router, Request, Response, NextFunction } from 'express';
import { taxiiClientService } from '../services/exchange/TAXIIClientService';
import { TAXIIFeedConfigSchema } from '@phishnetra/shared';

const router = Router();

// GET /api/cti-exchange/feeds
router.get('/feeds', (req: Request, res: Response) => {
  const feeds = taxiiClientService.listFeeds();
  res.json({ success: true, data: feeds });
});

// POST /api/cti-exchange/feeds
router.post('/feeds', (req: Request, res: Response, next: NextFunction) => {
  try {
    const parsed = TAXIIFeedConfigSchema.omit({ id: true, totalIndicatorsIngested: true }).parse(req.body);
    const feed = taxiiClientService.addFeed(parsed);
    res.status(201).json({ success: true, data: feed });
  } catch (error) {
    next(error);
  }
});

// POST /api/cti-exchange/feeds/:feedId/sync
router.post('/feeds/:feedId/sync', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { feedId } = req.params;
    const result = await taxiiClientService.syncFeed(feedId);
    res.json({ success: true, data: result });
  } catch (error) {
    next(error);
  }
});

// PATCH /api/cti-exchange/feeds/:feedId/status
router.patch('/feeds/:feedId/status', (req: Request, res: Response, next: NextFunction) => {
  try {
    const { feedId } = req.params;
    const { isActive } = req.body;
    if (typeof isActive !== 'boolean') {
      return res.status(400).json({ success: false, error: 'isActive must be a boolean' });
    }
    const updated = taxiiClientService.updateFeedStatus(feedId, isActive);
    res.json({ success: true, data: updated });
  } catch (error) {
    next(error);
  }
});

// GET /api/cti-exchange/indicators
router.get('/indicators', (req: Request, res: Response) => {
  const { indicatorType, tlp, feedId, limit } = req.query;
  const indicators = taxiiClientService.listIndicators({
    indicatorType: indicatorType as string,
    tlp: tlp as string,
    feedId: feedId as string,
    limit: limit ? parseInt(limit as string, 10) : undefined
  });
  res.json({ success: true, data: indicators, count: indicators.length });
});

// GET /api/cti-exchange/history
router.get('/history', (req: Request, res: Response) => {
  const history = taxiiClientService.getSyncHistory();
  res.json({ success: true, data: history });
});

// GET /api/cti-exchange/stats
router.get('/stats', (req: Request, res: Response) => {
  const stats = taxiiClientService.getExchangeStats();
  res.json({ success: true, data: stats });
});

export default router;
