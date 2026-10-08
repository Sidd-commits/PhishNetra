import { Request, Response, NextFunction } from 'express';
import { batchService } from '../services/queue/BatchService';
import { BatchJobRequest } from '@phishnetra/shared';

export class BatchController {
  public async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const payload = req.body as BatchJobRequest;
      const userId = req.user?.userId || null;

      if (!payload || !payload.urls) {
        res.status(400).json({ error: 'Validation Error', message: 'The urls field is required.' });
        return;
      }

      const response = await batchService.createBatchJob(userId, payload);
      res.status(202).json(response);
    } catch (error: any) {
      next(error);
    }
  }

  public async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const result = await batchService.getBatchJob(id);

      if (!result) {
        res.status(404).json({ error: 'Not Found', message: 'Batch job not found.' });
        return;
      }

      res.status(200).json(result);
    } catch (error: any) {
      next(error);
    }
  }

  public async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.userId;
      const limit = parseInt((req.query.limit as string) || '20', 10);
      const offset = parseInt((req.query.offset as string) || '0', 10);

      const result = await batchService.listBatchJobs(userId, limit, offset);
      res.status(200).json(result);
    } catch (error: any) {
      next(error);
    }
  }

  public async cancel(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const success = await batchService.cancelBatchJob(id);

      if (!success) {
        res.status(404).json({ error: 'Not Found', message: 'Batch job not found or cannot be cancelled.' });
        return;
      }

      res.status(200).json({ success: true, message: 'Batch job cancelled successfully.' });
    } catch (error: any) {
      next(error);
    }
  }

  public async export(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const format = (req.query.format as string) === 'json' ? 'json' : 'csv';

      const file = await batchService.exportBatchJob(id, format);
      res.setHeader('Content-Type', file.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
      res.send(file.data);
    } catch (error: any) {
      next(error);
    }
  }
}

export const batchController = new BatchController();
