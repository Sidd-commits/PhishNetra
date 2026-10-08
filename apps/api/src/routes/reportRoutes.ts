import { Router } from 'express';
import { reportController } from '../controllers/ReportController';
import { optionalAuth, requireAuth } from '../middleware/authMiddleware';

const router = Router();

router.post('/', optionalAuth, (req, res, next) => reportController.create(req, res, next));
router.get('/', optionalAuth, (req, res, next) => reportController.list(req, res, next));
router.get('/:id', optionalAuth, (req, res, next) => reportController.getById(req, res, next));
router.patch('/:id/moderate', requireAuth, (req, res, next) => reportController.moderate(req, res, next));

export default router;
