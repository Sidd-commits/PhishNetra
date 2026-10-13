import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/env';
import { settingsService } from '../services/settings/SettingsService';

export interface AuthenticatedUser {
  userId: string;
  role: string;
  email?: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  // 1. API Key Header Authentication (X-API-Key / X-API-Token)
  const apiKeyHeader = (req.headers['x-api-key'] || req.headers['x-api-token']) as string | undefined;
  if (apiKeyHeader) {
    const validKey = settingsService.validateApiKey(apiKeyHeader);
    if (validKey) {
      req.user = {
        userId: validKey.id,
        role: validKey.role,
        email: `apikey-${validKey.keyPrefix}@phishnetra.internal`
      };
      return next();
    }
  }

  // 2. JWT Bearer or Cookie Token
  let token: string | undefined;
  const authHeader = req.headers.authorization;
  if (authHeader && /^bearer\s+/i.test(authHeader)) {
    token = authHeader.replace(/^bearer\s+/i, '').trim();
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required to access this resource.'
    });
    return;
  }

  try {
    const decoded = jwt.verify(token, config.jwt.secret) as AuthenticatedUser;
    req.user = decoded;
    next();
  } catch (error: any) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or expired session token.'
    });
  }
};

export const optionalAuth = (req: Request, res: Response, next: NextFunction): void => {
  const apiKeyHeader = (req.headers['x-api-key'] || req.headers['x-api-token']) as string | undefined;
  if (apiKeyHeader) {
    const validKey = settingsService.validateApiKey(apiKeyHeader);
    if (validKey) {
      req.user = {
        userId: validKey.id,
        role: validKey.role,
        email: `apikey-${validKey.keyPrefix}@phishnetra.internal`
      };
      return next();
    }
  }

  let token: string | undefined;
  const authHeader = req.headers.authorization;
  if (authHeader && /^bearer\s+/i.test(authHeader)) {
    token = authHeader.replace(/^bearer\s+/i, '').trim();
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (token) {
    try {
      const decoded = jwt.verify(token, config.jwt.secret) as AuthenticatedUser;
      req.user = decoded;
    } catch {
      // ignore
    }
  }
  next();
};
