import { Router, Request, Response } from 'express';
import { HARForensicIngestSchema } from '@phishnetra/shared';
import { digitalForensicsService } from '../services/forensics/DigitalForensicsService';

export const digitalForensicsRouter = Router();

digitalForensicsRouter.post('/ingest-har', (req: Request, res: Response) => {
  try {
    const parseResult = HARForensicIngestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid HAR forensic ingest payload',
        details: parseResult.error.format()
      });
    }

    const artifact = digitalForensicsService.analyzeHAR(parseResult.data);
    return res.status(200).json({
      success: true,
      data: artifact
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: 'Digital forensics acquisition failed',
      details: err.message
    });
  }
});

digitalForensicsRouter.get('/artifacts', (_req: Request, res: Response) => {
  try {
    const artifacts = digitalForensicsService.listArtifacts();
    return res.status(200).json({
      success: true,
      data: artifacts
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: 'Failed to list forensic artifacts',
      details: err.message
    });
  }
});

digitalForensicsRouter.get('/artifacts/:id', (req: Request, res: Response) => {
  try {
    const artifact = digitalForensicsService.getArtifact(req.params.id);
    if (!artifact) {
      return res.status(404).json({
        success: false,
        error: `Forensic artifact '${req.params.id}' not found`
      });
    }
    return res.status(200).json({
      success: true,
      data: artifact
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: 'Failed to retrieve forensic artifact',
      details: err.message
    });
  }
});
