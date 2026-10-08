import { Router } from 'express';
import { domainController } from '../controllers/DomainController';
import { optionalAuth } from '../middleware/authMiddleware';

const router = Router();

router.get('/:domain', optionalAuth, (req, res, next) => domainController.getDossier(req, res, next));
router.post('/typosquatting', optionalAuth, (req, res, next) => domainController.scanTyposquatting(req, res, next));

export default router;
