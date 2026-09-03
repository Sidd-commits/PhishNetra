import { Request, Response } from 'express';
import { prisma } from '../db/prisma';
import { mlClient } from '../services/MLClientService';

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
      milestone: '1',
      dependencies: {
        database: dbStatus,
        mlService: mlHealth
      }
    });
  }
}

export const healthController = new HealthController();
