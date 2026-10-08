import { Request, Response, NextFunction } from 'express';
import { domainService } from '../services/DomainService';

export class DomainController {
  public async getDossier(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { domain } = req.params;
      if (!domain || domain.trim().length === 0) {
        res.status(400).json({ error: 'Validation Error', message: 'Domain name is required.' });
        return;
      }

      const dossier = await domainService.getDomainDossier(domain);
      res.status(200).json(dossier);
    } catch (error: any) {
      next(error);
    }
  }

  public async scanTyposquatting(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { domain } = req.body;
      if (!domain || typeof domain !== 'string') {
        res.status(400).json({ error: 'Validation Error', message: 'Target domain string is required in request body.' });
        return;
      }

      const result = domainService.analyzeTyposquatting(domain);
      res.status(200).json(result);
    } catch (error: any) {
      next(error);
    }
  }
}

export const domainController = new DomainController();
