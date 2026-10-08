import { Router, Request, Response } from 'express';
import { GenAIAnalysisRequestSchema } from '@phishnetra/shared';
import { genAIPhishingDefenseService } from '../services/genai/GenAIPhishingDefenseService';

export const genAIDefenseRouter = Router();

genAIDefenseRouter.post('/analyze', (req: Request, res: Response) => {
  try {
    const parseResult = GenAIAnalysisRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid GenAI analysis request payload',
        details: parseResult.error.format()
      });
    }

    const result = genAIPhishingDefenseService.analyzeContent(parseResult.data);
    return res.status(200).json({
      success: true,
      data: result
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: 'GenAI defense analysis failed',
      details: err.message
    });
  }
});
