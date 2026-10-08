import { Router } from 'express';
import { systemController } from '../controllers/SystemController';
import { optionalAuth } from '../middleware/authMiddleware';

const router = Router();

router.get('/metrics', optionalAuth, (req, res, next) => systemController.getMetrics(req, res, next));
router.get('/queue', optionalAuth, (req, res, next) => systemController.getQueue(req, res, next));
router.get('/cache', optionalAuth, (req, res, next) => systemController.getCache(req, res, next));

export default router;
