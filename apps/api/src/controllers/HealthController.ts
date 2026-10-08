import { Request, Response } from 'express';
import { prisma } from '../db/prisma';
import { mlClient } from '../services/MLClientService';
import { cacheService } from '../services/cache';

export class HealthController {
  public async getHealth(req: Request, res: Response): Promise<void> {
    let dbStatus = 'healthy';
    try {
      await prisma.$queryRaw`SELECT 1`;
    } catch (err: any) {
      dbStatus = `disconnected (${err.message})`;
    }

    const mlHealth = await mlClient.checkHealth();

    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'PhishNetra Node.js REST API',
      version: '0.1.0',
      milestone: '11',
      dependencies: {
        database: dbStatus,
        mlService: mlHealth
      }
    });
  }

  public async getReadiness(req: Request, res: Response): Promise<void> {
    let isDbReady = false;
    try {
      await prisma.$queryRaw`SELECT 1`;
      isDbReady = true;
    } catch {
      isDbReady = false;
    }

    const isMlReady = await mlClient.checkHealth();
    const isCacheReady = typeof (cacheService as any).isHealthy === 'function' ? (cacheService as any).isHealthy() : true;

    const isReady = isDbReady;

    res.status(isReady ? 200 : 503).json({
      ready: isReady,
      status: isReady ? 'READY' : 'DEGRADED',
      timestamp: new Date().toISOString(),
      checks: {
        database: isDbReady ? 'UP' : 'DOWN',
        mlService: isMlReady ? 'UP' : 'DOWN',
        cache: isCacheReady ? 'UP' : 'DOWN'
      }
    });
  }

  public async getLiveness(req: Request, res: Response): Promise<void> {
    res.status(200).json({
      alive: true,
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(process.uptime())
    });
  }
}

export const healthController = new HealthController();
