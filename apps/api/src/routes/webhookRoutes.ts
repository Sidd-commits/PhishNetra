import { Router, Request, Response } from 'express';
import { webhookNotificationService } from '../services/notifications/WebhookNotificationService';
import { CreateWebhookRequestSchema } from '@phishnetra/shared';

const router = Router();

/**
 * GET /api/notifications/webhooks
 * List configured webhook dispatch channels
 */
router.get('/webhooks', (_req: Request, res: Response, next) => {
  try {
    const list = webhookNotificationService.listWebhooks();
    res.json({
      success: true,
      data: list
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/notifications/webhooks
 * Create a new webhook subscription
 */
router.post('/webhooks', (req: Request, res: Response, next) => {
  try {
    const payload = CreateWebhookRequestSchema.parse(req.body);
    const created = webhookNotificationService.createWebhook(payload);
    res.status(201).json({
      success: true,
      data: created
    });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/notifications/webhooks/:id
 * Delete webhook configuration
 */
router.delete('/webhooks/:id', (req: Request, res: Response, next) => {
  try {
    const deleted = webhookNotificationService.deleteWebhook(req.params.id);
    if (!deleted) {
      res.status(404).json({ error: 'Not Found', message: `Webhook '${req.params.id}' not found` });
      return;
    }
    res.json({
      success: true,
      message: 'Webhook configuration removed'
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/notifications/webhooks/:id/test
 * Dispatch test payload to verify connectivity
 */
router.post('/webhooks/:id/test', async (req: Request, res: Response, next) => {
  try {
    const log = await webhookNotificationService.testWebhook(req.params.id);
    res.json({
      success: true,
      data: log
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/notifications/logs
 * Retrieve recent delivery logs
 */
router.get('/logs', (req: Request, res: Response, next) => {
  try {
    const limit = parseInt(req.query.limit as string, 10) || 50;
    const logs = webhookNotificationService.getLogs(limit);
    res.json({
      success: true,
      data: logs
    });
  } catch (error) {
    next(error);
  }
});

export default router;
