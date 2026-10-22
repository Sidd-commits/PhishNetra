import { Router, Request, Response } from 'express';
import { emailIngestionService } from '../services/ingestion/EmailIngestionService';
import { attachmentAnalysisService } from '../services/ingestion/AttachmentAnalysisService';
import {
  EmailAnalysisRequestSchema,
  RawIOCExtractionRequestSchema,
  AttachmentAnalysisRequestSchema
} from '@phishnetra/shared';

import { validateBody } from '../middleware/validateRequest';

const router = Router();

/**
 * POST /api/ingest/attachment
 * Upload and inspect email attachment (PDF, HTML, TXT, DOCX, EML) to extract and analyze all embedded URLs
 */
router.post('/attachment', validateBody(AttachmentAnalysisRequestSchema), async (req: Request, res: Response, next) => {
  try {
    const result = await attachmentAnalysisService.analyzeAttachment(req.body);
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/ingest/email
 * Ingest and analyze raw RFC 822 email text, check spoofing and evaluate embedded links
 */
router.post('/email', async (req: Request, res: Response, next) => {
  try {
    const payload = EmailAnalysisRequestSchema.parse(req.body);
    const result = await emailIngestionService.analyzeEmail(payload);
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/ingest/raw-ioc
 * Extract and defang URLs, IPs, domains, hashes from unstructured raw text
 */
router.post('/raw-ioc', (req: Request, res: Response, next) => {
  try {
    const { rawText } = RawIOCExtractionRequestSchema.parse(req.body);
    const extracted = emailIngestionService.extractRawIOCs(rawText);
    res.json({
      success: true,
      data: extracted
    });
  } catch (error) {
    next(error);
  }
});

export default router;

