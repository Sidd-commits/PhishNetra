import { Router, Request, Response } from 'express';
import { d3fendMappingService } from '../services/d3fend/D3FENDMappingService';

export const d3fendRouter = Router();

// GET /api/d3fend/matrix
d3fendRouter.get('/matrix', (_req: Request, res: Response) => {
  const matrix = d3fendMappingService.getD3FENDCoverage();
  return res.status(200).json({ success: true, data: matrix });
});
