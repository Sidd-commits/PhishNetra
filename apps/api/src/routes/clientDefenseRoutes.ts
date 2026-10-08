import { Router, Request, Response } from 'express';
import { ClientGuardConfigSchema, ClientTamperEventSchema } from '@phishnetra/shared';
import { clientTamperDefenseService } from '../services/defense/ClientTamperDefenseService';

export const clientDefenseRouter = Router();

// POST /api/client-defense/generate
clientDefenseRouter.post('/generate', (req: Request, res: Response) => {
  try {
    const config = ClientGuardConfigSchema.parse(req.body);
    const result = clientTamperDefenseService.generateGuardScript(config);
    return res.status(200).json({ success: true, data: result });
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: { code: 'INVALID_GUARD_CONFIG', message: error.message }
    });
  }
});

// POST /api/client-defense/beacon (Ingest tampering report)
clientDefenseRouter.post('/beacon', (req: Request, res: Response) => {
  try {
    // Allows raw beacon payload parsing
    const payload = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown Browser';

    const event = clientTamperDefenseService.recordTamperEvent({
      targetDomain: payload.targetDomain || 'unknown-client-domain',
      tamperType: payload.tamperType || 'DOM_OVERLAY_INJECTED',
      clientIp,
      userAgent,
      payloadDetails: payload.payloadDetails || {},
      severity: payload.severity || 'HIGH'
    });

    return res.status(200).json({ success: true, data: event });
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: { code: 'BEACON_RECORD_FAILED', message: error.message }
    });
  }
});

// GET /api/client-defense/events
clientDefenseRouter.get('/events', (_req: Request, res: Response) => {
  const events = clientTamperDefenseService.listTamperEvents();
  return res.status(200).json({ success: true, data: events });
});
