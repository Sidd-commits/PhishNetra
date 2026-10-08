import { Router, Request, Response } from 'express';
import { playbookOrchestrationEngine } from '../services/playbooks/PlaybookOrchestrationEngine';
import { CreatePlaybookRequestSchema, TriggerPlaybookRequestSchema } from '@phishnetra/shared';
import { requireAuth } from '../middleware/authMiddleware';

const router = Router();

// List all playbooks
router.get('/', requireAuth, (req: Request, res: Response) => {
  try {
    const playbooks = playbookOrchestrationEngine.listPlaybooks();
    res.status(200).json({ success: true, data: playbooks });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get execution runs
router.get('/runs', requireAuth, (req: Request, res: Response) => {
  try {
    const playbookId = req.query.playbookId as string | undefined;
    const runs = playbookOrchestrationEngine.listExecutionRuns(playbookId);
    res.status(200).json({ success: true, data: runs });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get single playbook
router.get('/:id', requireAuth, (req: Request, res: Response) => {
  try {
    const playbook = playbookOrchestrationEngine.getPlaybook(req.params.id);
    if (!playbook) {
      return res.status(404).json({ success: false, error: 'Playbook not found' });
    }
    res.status(200).json({ success: true, data: playbook });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Create new playbook
router.post('/', requireAuth, (req: Request, res: Response) => {
  try {
    const parsed = CreatePlaybookRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.issues[0]?.message });
    }
    const created = playbookOrchestrationEngine.createPlaybook(parsed.data);
    res.status(201).json({ success: true, data: created });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Update playbook
router.patch('/:id', requireAuth, (req: Request, res: Response) => {
  try {
    const updated = playbookOrchestrationEngine.updatePlaybook(req.params.id, req.body);
    if (!updated) {
      return res.status(404).json({ success: false, error: 'Playbook not found' });
    }
    res.status(200).json({ success: true, data: updated });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Delete playbook
router.delete('/:id', requireAuth, (req: Request, res: Response) => {
  try {
    const ok = playbookOrchestrationEngine.deletePlaybook(req.params.id);
    if (!ok) {
      return res.status(404).json({ success: false, error: 'Playbook not found' });
    }
    res.status(200).json({ success: true });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Trigger playbook run
router.post('/trigger', requireAuth, async (req: Request, res: Response) => {
  try {
    const parsed = TriggerPlaybookRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.issues[0]?.message });
    }
    const user = (req as any).user?.name || 'SOC_ANALYST';
    const run = await playbookOrchestrationEngine.triggerPlaybook(parsed.data, user);
    res.status(200).json({ success: true, data: run });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
