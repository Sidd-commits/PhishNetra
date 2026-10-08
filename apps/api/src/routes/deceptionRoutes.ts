import { Router, Request, Response } from 'express';
import { requireAuth } from '../middleware/authMiddleware';
import { CreateCanaryTokenRequestSchema } from '@phishnetra/shared';
import { canaryDeceptionService } from '../services/deception/CanaryDeceptionService';

const router = Router();

// GET /api/deception/tokens - List all deception canaries
router.get('/tokens', requireAuth, (req: Request, res: Response) => {
  try {
    const tokens = canaryDeceptionService.listTokens();
    return res.json({ success: true, count: tokens.length, data: tokens });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to list canary tokens', details: err.message });
  }
});

// GET /api/deception/tokens/:id
router.get('/tokens/:id', requireAuth, (req: Request, res: Response) => {
  try {
    const token = canaryDeceptionService.getToken(req.params.id);
    if (!token) {
      return res.status(404).json({ error: 'Canary token not found' });
    }
    return res.json({ success: true, data: token });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to retrieve canary token', details: err.message });
  }
});

// POST /api/deception/tokens - Create new canary token
router.post('/tokens', requireAuth, (req: Request, res: Response) => {
  try {
    const parseResult = CreateCanaryTokenRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: 'Invalid token creation payload', details: parseResult.error.format() });
    }

    const actor = {
      id: req.user?.userId || 'usr-analyst-1',
      name: req.user?.email ? req.user.email.split('@')[0] : 'SOC Analyst'
    };

    const token = canaryDeceptionService.createToken(parseResult.data, actor);
    return res.status(201).json({ success: true, data: token });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to create canary token', details: err.message });
  }
});

// PATCH /api/deception/tokens/:id/status - Toggle active/disabled
router.patch('/tokens/:id/status', requireAuth, (req: Request, res: Response) => {
  try {
    const { status } = req.body;
    if (!['ACTIVE', 'DISABLED', 'REVOKED'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status value' });
    }

    const actor = {
      id: req.user?.userId || 'usr-analyst-1',
      name: req.user?.email ? req.user.email.split('@')[0] : 'SOC Analyst'
    };

    const token = canaryDeceptionService.toggleTokenStatus(req.params.id, status, actor);
    if (!token) {
      return res.status(404).json({ error: 'Canary token not found' });
    }
    return res.json({ success: true, data: token });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to update token status', details: err.message });
  }
});

// GET /api/deception/triggers - List recorded tripwire trigger events
router.get('/triggers', requireAuth, (req: Request, res: Response) => {
  try {
    const triggers = canaryDeceptionService.listTriggers();
    return res.json({ success: true, count: triggers.length, data: triggers });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to list trigger events', details: err.message });
  }
});

// PUBLIC BEACON LISTENER: GET /api/deception/beacon/:tokenString (Returns 1x1 transparent GIF)
router.get('/beacon/:tokenString', (req: Request, res: Response) => {
  try {
    const rawToken = req.params.tokenString.replace(/\.gif$/i, '');
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === 'string') headers[k] = v;
    }

    canaryDeceptionService.recordTrigger(rawToken, {
      sourceIp: req.ip || req.socket.remoteAddress || '198.51.100.1',
      userAgent: req.headers['user-agent'] || 'Unknown Agent',
      headers,
      payload: null
    });

    // 1x1 Transparent GIF buffer
    const gifBuffer = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
    res.setHeader('Content-Type', 'image/gif');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    return res.status(200).send(gifBuffer);
  } catch (err: any) {
    return res.status(200).send(Buffer.from(''));
  }
});

// PUBLIC BEACON LISTENER: POST /api/deception/beacon/:tokenString (For JS beacon postbacks)
router.post('/beacon/:tokenString', (req: Request, res: Response) => {
  try {
    const rawToken = req.params.tokenString;
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === 'string') headers[k] = v;
    }

    const trigger = canaryDeceptionService.recordTrigger(rawToken, {
      sourceIp: req.ip || req.socket.remoteAddress || '198.51.100.1',
      userAgent: req.headers['user-agent'] || 'Unknown Agent',
      headers,
      payload: typeof req.body === 'string' ? req.body : JSON.stringify(req.body)
    });

    return res.json({ success: true, registered: !!trigger });
  } catch (err: any) {
    return res.status(200).json({ success: true });
  }
});

export default router;
