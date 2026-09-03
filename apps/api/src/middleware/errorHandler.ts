import { Request, Response, NextFunction } from 'express';

/**
 * Centralized application error handling middleware.
 */
export const errorHandler = (
  err: any,
  req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  next: NextFunction
): void => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  if (statusCode >= 500) {
    console.error(`[UnhandledError] ${req.method} ${req.originalUrl}:`, err);
  }

  res.status(statusCode).json({
    error: statusCode === 500 ? 'Internal Server Error' : err.name || 'Error',
    message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};
