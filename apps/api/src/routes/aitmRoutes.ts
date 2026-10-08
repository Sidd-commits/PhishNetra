import { Router, Request, Response } from 'express';
import { AiTMSessionScanRequestSchema } from '@phishnetra/shared';
import { AiTMDefenseService } from '../services/aitm/AiTMDefenseService';
import { auditLogService } from '../services/audit/AuditLogService';

export const aitmRouter = Router();

// POST /api/aitm/scan — Scan session or URL for AiTM reverse proxy signatures
aitmRouter.post('/scan', async (req: Request, res: Response) => {
  try {
    const parseResult = AiTMSessionScanRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid AiTM scan request',
          details: parseResult.error.format()
        }
      });
    }

    const result = AiTMDefenseService.scanSession(parseResult.data);

    if (result.isAiTMProxy) {
      auditLogService.log({
        actor: req.body.userEmail || 'system:aitm_guard',
        action: 'AITM_PROXY_INTERCEPTED',
        category: 'SECURITY',
        severity: 'CRITICAL',
        target: result.targetUrl,
        details: `Detected AiTM reverse proxy threat (${result.threatType}) with risk score ${result.riskScore}. Recommended action: ${result.recommendedAction}`
      });
    }

    return res.json({
      success: true,
      data: result
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: err.message || 'Failed to scan for AiTM reverse proxy'
      }
    });
  }
});
