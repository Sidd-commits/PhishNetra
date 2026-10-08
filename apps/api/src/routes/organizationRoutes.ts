import { Router, Request, Response } from 'express';
import { organizationService } from '../services/organization/OrganizationService';
import { requireAuth } from '../middleware/authMiddleware';

const router = Router();

// Get workspace profile
router.get('/workspace', requireAuth, async (req: Request, res: Response) => {
  try {
    const ws = await organizationService.getWorkspace();
    res.status(200).json({ success: true, data: ws });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Update security policy
router.patch('/policy', requireAuth, async (req: Request, res: Response) => {
  try {
    const actor = (req as any).user?.email || 'admin';
    const updated = await organizationService.updateSecurityPolicy(req.body, actor);
    res.status(200).json({ success: true, data: updated });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Invite member
router.post('/members', requireAuth, async (req: Request, res: Response) => {
  try {
    const { name, email, role } = req.body;
    if (!name || !email || !role) {
      res.status(400).json({ success: false, error: 'Name, email, and role are required' });
      return;
    }
    const actor = (req as any).user?.email || 'admin';
    const member = await organizationService.inviteMember(name, email, role, actor);
    res.status(201).json({ success: true, data: member });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Remove member
router.delete('/members/:id', requireAuth, async (req: Request, res: Response) => {
  try {
    const actor = (req as any).user?.email || 'admin';
    const removed = await organizationService.removeMember(req.params.id, actor);
    if (!removed) {
      res.status(404).json({ success: false, error: 'Member not found' });
      return;
    }
    res.status(200).json({ success: true, message: 'Member removed successfully' });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
