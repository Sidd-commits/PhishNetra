import { Router, Request, Response } from 'express';
import { auditLogService } from '../services/audit/AuditLogService';
import { AuditLogCategory, AuditLogSeverity } from '@phishnetra/shared';

const router = Router();

// GET /api/audit-logs - Query audit trail with pagination and filters
router.get('/', (req: Request, res: Response) => {
  try {
    const { category, severity, actor, search, limit, offset } = req.query;

    const result = auditLogService.getLogs({
      category: category ? (category as AuditLogCategory) : undefined,
      severity: severity ? (severity as AuditLogSeverity) : undefined,
      actor: actor ? String(actor) : undefined,
      search: search ? String(search) : undefined,
      limit: limit ? parseInt(String(limit), 10) : 50,
      offset: offset ? parseInt(String(offset), 10) : 0
    });

    return res.status(200).json({
      success: true,
      data: result
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to retrieve audit logs' }
    });
  }
});

// GET /api/audit-logs/export - Export audit trail as CSV
router.get('/export', (req: Request, res: Response) => {
  try {
    const { category, severity, actor, search } = req.query;

    const csvContent = auditLogService.exportCsv({
      category: category ? (category as AuditLogCategory) : undefined,
      severity: severity ? (severity as AuditLogSeverity) : undefined,
      actor: actor ? String(actor) : undefined,
      search: search ? String(search) : undefined
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="phishnetra-soc-audit-trail.csv"');
    return res.status(200).send(csvContent);
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to export audit logs' }
    });
  }
});

export default router;
