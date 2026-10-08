import { Router, Request, Response } from 'express';
import { requireAuth } from '../middleware/authMiddleware';
import { CopilotChatRequestSchema } from '@phishnetra/shared';
import { threatCopilotService } from '../services/copilot/ThreatCopilotService';

const router = Router();

// GET /api/copilot/templates
router.get('/templates', requireAuth, (req: Request, res: Response) => {
  try {
    const templates = threatCopilotService.getPromptTemplates();
    return res.json({ success: true, data: templates });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to fetch prompt templates', details: err.message });
  }
});

// POST /api/copilot/chat
router.post('/chat', requireAuth, async (req: Request, res: Response) => {
  try {
    const parseResult = CopilotChatRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({ error: 'Invalid copilot chat request', details: parseResult.error.format() });
    }

    const actor = {
      id: req.user?.userId || 'usr-analyst-1',
      name: req.user?.email ? req.user.email.split('@')[0] : 'SOC Lead Analyst',
      role: req.user?.role || 'ANALYST'
    };

    const response = await threatCopilotService.processChat(parseResult.data, actor);
    return res.json({ success: true, data: response });
  } catch (err: any) {
    return res.status(500).json({ error: 'Copilot inference failed', details: err.message });
  }
});

export default router;
