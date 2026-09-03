import { Router } from 'express';
import { authController } from '../controllers/AuthController';
import { validateBody } from '../middleware/validateRequest';
import { requireAuth } from '../middleware/authMiddleware';
import { RegisterRequestSchema, LoginRequestSchema } from '@phishnetra/shared';

const router = Router();

router.post(
  '/register',
  validateBody(RegisterRequestSchema),
  (req, res, next) => authController.register(req, res, next)
);

router.post(
  '/login',
  validateBody(LoginRequestSchema),
  (req, res, next) => authController.login(req, res, next)
);

router.post('/logout', (req, res) => authController.logout(req, res));

router.get('/me', requireAuth, (req, res, next) => authController.getMe(req, res, next));

export default router;
