import { Request, Response, NextFunction } from 'express';
import { analysisQueue } from '../services/queue/AsyncAnalysisQueue';
import { cache } from '../services/cache/CacheManager';

export class SystemController {
  public async getQueue(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const metrics = analysisQueue.getMetrics();
      res.status(200).json(metrics);
    } catch (error: any) {
      next(error);
    }
  }

  public async getCache(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const stats = await cache.getStats();
      res.status(200).json(stats);
    } catch (error: any) {
      next(error);
    }
  }

  public async getMetrics(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const [queue, cacheStats] = await Promise.all([
        Promise.resolve(analysisQueue.getMetrics()),
        cache.getStats()
      ]);

      res.status(200).json({
        queue,
        cache: cacheStats,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      next(error);
    }
  }
}

export const systemController = new SystemController();
