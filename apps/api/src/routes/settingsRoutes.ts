import { Router, Request, Response } from 'express';
import { settingsService } from '../services/settings/SettingsService';
import { auditLogService } from '../services/audit/AuditLogService';
import {
  UpdateSystemConfigRequestSchema,
  CreateApiKeyRequestSchema
} from '@phishnetra/shared';

const router = Router();

// GET /api/settings/config - Retrieve current calibration & system configuration
router.get('/config', (req: Request, res: Response) => {
  try {
    const config = settingsService.getConfig();
    return res.status(200).json({
      success: true,
      data: config
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to retrieve system configuration' }
    });
  }
});

// PATCH /api/settings/config - Update weights, thresholds, providers, or whitelists
router.patch('/config', (req: Request, res: Response) => {
  try {
    const parseResult = UpdateSystemConfigRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: {
          message: 'Invalid configuration update payload',
          details: parseResult.error.format()
        }
      });
    }

    const actor = (req as any).user?.email || 'admin@phishnetra.internal';
    const updated = settingsService.updateConfig(parseResult.data, actor);

    auditLogService.log({
      actor,
      action: 'SYSTEM_CONFIG_UPDATED',
      category: 'CONFIG',
      severity: 'INFO',
      target: 'SystemConfig',
      details: `Updated system configuration & weights`
    });

    return res.status(200).json({
      success: true,
      data: updated
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to update system configuration' }
    });
  }
});

// POST /api/settings/reset - Reset calibration to factory defaults
router.post('/reset', (req: Request, res: Response) => {
  try {
    const actor = (req as any).user?.email || 'admin@phishnetra.internal';
    const config = settingsService.resetToDefaults(actor);

    auditLogService.log({
      actor,
      action: 'SYSTEM_CONFIG_RESET',
      category: 'CONFIG',
      severity: 'WARNING',
      target: 'SystemConfig',
      details: 'Reset system risk weights and thresholds to default factory baseline'
    });

    return res.status(200).json({
      success: true,
      data: config
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to reset system configuration' }
    });
  }
});

// GET /api/settings/api-keys - List API Keys
router.get('/api-keys', (req: Request, res: Response) => {
  try {
    const keys = settingsService.listApiKeys();
    return res.status(200).json({
      success: true,
      data: keys
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to list API keys' }
    });
  }
});

// POST /api/settings/api-keys - Create API Key
router.post('/api-keys', (req: Request, res: Response) => {
  try {
    const parseResult = CreateApiKeyRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: {
          message: 'Invalid API key creation payload',
          details: parseResult.error.format()
        }
      });
    }

    const result = settingsService.createApiKey(parseResult.data);
    const actor = (req as any).user?.email || 'admin@phishnetra.internal';

    auditLogService.log({
      actor,
      action: 'API_KEY_CREATED',
      category: 'AUTH',
      severity: 'WARNING',
      target: result.apiKey.name,
      details: `Generated new API key (${result.apiKey.keyPrefix}) with role ${result.apiKey.role}`
    });

    return res.status(201).json({
      success: true,
      data: result
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to create API key' }
    });
  }
});

// DELETE /api/settings/api-keys/:id - Revoke API Key
router.delete('/api-keys/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const revoked = settingsService.revokeApiKey(id);
    if (!revoked) {
      return res.status(404).json({
        success: false,
        error: { message: `API key with ID ${id} not found` }
      });
    }

    const actor = (req as any).user?.email || 'admin@phishnetra.internal';
    auditLogService.log({
      actor,
      action: 'API_KEY_REVOKED',
      category: 'AUTH',
      severity: 'WARNING',
      target: id,
      details: `Revoked API key ID ${id}`
    });

    return res.status(200).json({
      success: true,
      message: 'API Key revoked successfully'
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to revoke API key' }
    });
  }
});

export default router;
