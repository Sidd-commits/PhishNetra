import { Router } from 'express';
import { batchController } from '../controllers/BatchController';
import { optionalAuth, requireAuth } from '../middleware/authMiddleware';

const router = Router();

router.post('/', optionalAuth, (req, res, next) => batchController.create(req, res, next));
router.get('/', optionalAuth, (req, res, next) => batchController.list(req, res, next));
router.get('/:id', optionalAuth, (req, res, next) => batchController.getById(req, res, next));
router.post('/:id/cancel', optionalAuth, (req, res, next) => batchController.cancel(req, res, next));
router.get('/:id/export', optionalAuth, (req, res, next) => batchController.export(req, res, next));

export default router;
