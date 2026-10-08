import { Router, Request, Response } from 'express';
import { requireAuth } from '../middleware/authMiddleware';
import { LaunchTarpitTaskRequestSchema } from '@phishnetra/shared';
import { phishingTarpitService } from '../services/tarpit/PhishingTarpitService';

const router = Router();

// GET /api/tarpit/tasks - List all active and past tarpit flooding tasks
router.get('/tasks', requireAuth, (req: Request, res: Response) => {
  try {
    const tasks = phishingTarpitService.listTasks();
    return res.json({ success: true, count: tasks.length, data: tasks });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to list tarpit tasks', details: err.message });
  }
});

// GET /api/tarpit/tasks/:id - Get single task
router.get('/tasks/:id', requireAuth, (req: Request, res: Response) => {
  try {
    const task = phishingTarpitService.getTask(req.params.id);
    if (!task) {
      return res.status(404).json({ error: 'Tarpit task not found' });
    }
    return res.json({ success: true, data: task });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to retrieve tarpit task', details: err.message });
  }
});

// POST /api/tarpit/tasks - Launch new synthetic credential flooding tarpit
router.post('/tasks', requireAuth, (req: Request, res: Response) => {
  try {
    const parseResult = LaunchTarpitTaskRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: 'Invalid tarpit launch payload', details: parseResult.error.format() });
    }

    const actor = {
      id: req.user?.userId || 'usr-analyst-1',
      name: req.user?.email ? req.user.email.split('@')[0] : 'SOC Analyst'
    };

    const task = phishingTarpitService.launchTask(parseResult.data, actor);
    return res.status(201).json({ success: true, data: task });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to launch tarpit task', details: err.message });
  }
});

// POST /api/tarpit/tasks/:id/stop - Stop active tarpit task
router.post('/tasks/:id/stop', requireAuth, (req: Request, res: Response) => {
  try {
    const actor = {
      id: req.user?.userId || 'usr-analyst-1',
      name: req.user?.email ? req.user.email.split('@')[0] : 'SOC Analyst'
    };

    const task = phishingTarpitService.stopTask(req.params.id, actor);
    if (!task) {
      return res.status(404).json({ error: 'Tarpit task not found' });
    }
    return res.json({ success: true, data: task });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to stop tarpit task', details: err.message });
  }
});

export default router;
