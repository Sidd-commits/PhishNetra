import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/AuthService';
import { RegisterRequest, LoginRequest } from '@phishnetra/shared';

export class AuthController {
  public async register(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const payload = req.body as RegisterRequest;
      const result = await authService.register(payload);

      res.cookie('token', result.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      res.status(201).json(result);
    } catch (error) {
      next(error);
    }
  }

  public async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const payload = req.body as LoginRequest;
      const result = await authService.login(payload);

      res.cookie('token', result.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  }

  public async logout(req: Request, res: Response): Promise<void> {
    res.clearCookie('token');
    res.status(200).json({ message: 'Logged out successfully' });
  }

  public async getMe(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user?.userId) {
        res.status(401).json({ error: 'Unauthorized', message: 'No active session' });
        return;
      }
      const profile = await authService.getProfile(req.user.userId);
      res.status(200).json({ user: profile });
    } catch (error) {
      next(error);
    }
  }
}

export const authController = new AuthController();
