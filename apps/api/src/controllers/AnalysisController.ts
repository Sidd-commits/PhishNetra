import { Request, Response, NextFunction } from 'express';
import { analysisService } from '../services/AnalysisService';
import { AnalysisRequest } from '@phishnetra/shared';

export class AnalysisController {
  public async analyze(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const payload = req.body as AnalysisRequest;
      const userId = req.user?.userId;

      const result = await analysisService.analyze(payload.url, userId, payload.analyzePage ?? true);
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  }

  public async getHistory(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string || '20', 10)));
      const offset = Math.max(0, parseInt(req.query.offset as string || '0', 10));

      // If user is Admin, Analyst, or unauthenticated visitor on overview, show recent telemetry; otherwise show user's own
      const userId = req.user?.role === 'ADMIN' || req.user?.role === 'ANALYST' || !req.user ? undefined : req.user.userId;

      const history = await analysisService.getHistory(userId, limit, offset);
      res.status(200).json(history);
    } catch (error) {
      next(error);
    }
  }

  public async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const result = await analysisService.getById(id);
      if (!result) {
        res.status(404).json({ error: 'Not Found', message: 'Analysis record not found' });
        return;
      }
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  }
}

export const analysisController = new AnalysisController();
