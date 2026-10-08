import { Router, Request, Response } from 'express';
import { ComplianceFrameworkSchema } from '@phishnetra/shared';
import { ComplianceAuditService } from '../services/compliance/ComplianceAuditService';

export const complianceRouter = Router();

// GET /api/compliance/audit — Run automated compliance audit
complianceRouter.get('/audit', async (req: Request, res: Response) => {
  try {
    const rawFramework = (req.query.framework as string) || 'NIST_CSF_2';
    const parseResult = ComplianceFrameworkSchema.safeParse(rawFramework);

    const framework = parseResult.success ? parseResult.data : 'NIST_CSF_2';
    const result = ComplianceAuditService.runAudit(framework);

    return res.json({
      success: true,
      data: result
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: err.message || 'Failed to execute compliance audit'
      }
    });
  }
});
