import { Router } from 'express';
import { healthController } from '../controllers/HealthController';

const router = Router();

router.get('/', (req, res) => healthController.getHealth(req, res));
router.get('/ready', (req, res) => healthController.getReadiness(req, res));
router.get('/live', (req, res) => healthController.getLiveness(req, res));

export default router;
