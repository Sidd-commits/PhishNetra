import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

/**
 * Middleware factory for validating Express request bodies against Zod schemas.
 */
export const validateBody = (schema: ZodSchema) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      req.body = await schema.parseAsync(req.body);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const issues = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message
        }));
        res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid request payload',
          details: issues
        });
        return;
      }
      next(error);
    }
  };
};
