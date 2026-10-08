import { Router, Request, Response } from 'express';
import { takedownService } from '../services/takedown/TakedownService';
import { CreateTakedownRequestSchema } from '@phishnetra/shared';
import { requireAuth } from '../middleware/authMiddleware';

const router = Router();

// List all notices
router.get('/', requireAuth, async (req: Request, res: Response) => {
  try {
    const status = req.query.status as string;
    const notices = await takedownService.listNotices(status);
    res.status(200).json({
      success: true,
      data: notices
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get notice by ID
router.get('/:id', requireAuth, async (req: Request, res: Response) => {
  try {
    const notice = await takedownService.getNoticeById(req.params.id);
    if (!notice) {
      res.status(404).json({ success: false, error: 'Takedown notice not found' });
      return;
    }
    res.status(200).json({ success: true, data: notice });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Create new takedown notice
router.post('/', requireAuth, async (req: Request, res: Response) => {
  try {
    const validated = CreateTakedownRequestSchema.parse(req.body);
    const actor = (req as any).user?.email || 'soc_analyst';
    const notice = await takedownService.createTakedownNotice(validated, actor);
    res.status(201).json({ success: true, data: notice });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Update notice status
router.patch('/:id/status', requireAuth, async (req: Request, res: Response) => {
  try {
    const { status } = req.body;
    if (!status) {
      res.status(400).json({ success: false, error: 'Status is required' });
      return;
    }
    const actor = (req as any).user?.email || 'soc_analyst';
    const updated = await takedownService.updateNoticeStatus(req.params.id, status, actor);
    if (!updated) {
      res.status(404).json({ success: false, error: 'Takedown notice not found' });
      return;
    }
    res.status(200).json({ success: true, data: updated });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
