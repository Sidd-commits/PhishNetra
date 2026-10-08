import { Request, Response, NextFunction } from 'express';
import { reportService } from '../services/ReportService';
import { CreateReportRequest, ReportModerationRequest } from '@phishnetra/shared';

export class ReportController {
  public async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const payload = req.body as CreateReportRequest;
      const userId = req.user?.userId || null;
      const userName = req.user?.email ? req.user.email.split('@')[0] : null;

      if (!payload || !payload.url || !payload.description) {
        res.status(400).json({ error: 'Validation Error', message: 'The url and description fields are required.' });
        return;
      }

      const report = await reportService.createReport(userId, userName, payload);
      res.status(201).json(report);
    } catch (error: any) {
      next(error);
    }
  }

  public async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const status = req.query.status as any;
      const reportType = req.query.reportType as any;
      const domain = req.query.domain as string;
      const limit = parseInt((req.query.limit as string) || '50', 10);
      const offset = parseInt((req.query.offset as string) || '0', 10);

      const result = await reportService.listReports({
        status,
        reportType,
        domain,
        limit,
        offset
      });
      res.status(200).json(result);
    } catch (error: any) {
      next(error);
    }
  }

  public async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const report = await reportService.getReport(id);

      if (!report) {
        res.status(404).json({ error: 'Not Found', message: 'Report not found.' });
        return;
      }

      res.status(200).json(report);
    } catch (error: any) {
      next(error);
    }
  }

  public async moderate(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const payload = req.body as ReportModerationRequest;
      const moderatorName = req.user?.email || 'SOC Analyst';

      if (!payload || !payload.status) {
        res.status(400).json({ error: 'Validation Error', message: 'The status field is required.' });
        return;
      }

      const report = await reportService.moderateReport(id, moderatorName, payload);
      res.status(200).json(report);
    } catch (error: any) {
      next(error);
    }
  }
}

export const reportController = new ReportController();
