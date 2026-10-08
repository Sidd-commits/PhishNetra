import { Router, Request, Response } from 'express';
import { requireAuth } from '../middleware/authMiddleware';
import { CreateRBISessionRequestSchema } from '@phishnetra/shared';
import { remoteBrowserIsolationService } from '../services/rbi/RemoteBrowserIsolationService';

const router = Router();

// GET /api/rbi/sessions - List active and historical RBI sessions
router.get('/sessions', requireAuth, (req: Request, res: Response) => {
  try {
    const sessions = remoteBrowserIsolationService.listSessions();
    return res.json({ success: true, count: sessions.length, data: sessions });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to list RBI sessions', details: err.message });
  }
});

// GET /api/rbi/sessions/:id - Get session details
router.get('/sessions/:id', requireAuth, (req: Request, res: Response) => {
  try {
    const session = remoteBrowserIsolationService.getSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'RBI session not found' });
    }
    return res.json({ success: true, data: session });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to retrieve RBI session', details: err.message });
  }
});

// POST /api/rbi/sessions - Spin up new isolated container session
router.post('/sessions', requireAuth, (req: Request, res: Response) => {
  try {
    const parseResult = CreateRBISessionRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: 'Invalid RBI session request', details: parseResult.error.format() });
    }

    const actor = {
      id: req.user?.userId || 'usr-analyst-1',
      name: req.user?.email ? req.user.email.split('@')[0] : 'SOC Analyst'
    };

    const session = remoteBrowserIsolationService.createSession(parseResult.data, actor);
    return res.status(201).json({ success: true, data: session });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to initialize RBI session', details: err.message });
  }
});

// POST /api/rbi/sessions/:id/terminate - Terminate isolated sandbox session
router.post('/sessions/:id/terminate', requireAuth, (req: Request, res: Response) => {
  try {
    const actor = {
      id: req.user?.userId || 'usr-analyst-1',
      name: req.user?.email ? req.user.email.split('@')[0] : 'SOC Analyst'
    };

    const session = remoteBrowserIsolationService.terminateSession(req.params.id, actor);
    if (!session) {
      return res.status(404).json({ error: 'RBI session not found' });
    }
    return res.json({ success: true, data: session });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to terminate RBI session', details: err.message });
  }
});

export default router;
