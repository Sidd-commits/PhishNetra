import { Router } from 'express';
import { analysisController } from '../controllers/AnalysisController';
import { validateBody } from '../middleware/validateRequest';
import { requireAuth, optionalAuth } from '../middleware/authMiddleware';
import { AnalysisRequestSchema } from '@phishnetra/shared';

const router = Router();

router.post(
  '/',
  optionalAuth,
  validateBody(AnalysisRequestSchema),
  (req, res, next) => analysisController.analyze(req, res, next)
);

router.get(
  '/history',
  requireAuth,
  (req, res, next) => analysisController.getHistory(req, res, next)
);

router.get(
  '/:id',
  (req, res, next) => analysisController.getById(req, res, next)
);

export default router;
