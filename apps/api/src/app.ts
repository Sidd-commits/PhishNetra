import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

import { config } from './config/env';
import authRoutes from './routes/authRoutes';
import analysisRoutes from './routes/analysisRoutes';
import batchRoutes from './routes/batchRoutes';
import domainRoutes from './routes/domainRoutes';
import reportRoutes from './routes/reportRoutes';
import systemRoutes from './routes/systemRoutes';
import healthRoutes from './routes/healthRoutes';
import { errorHandler } from './middleware/errorHandler';

export const createApp = (): express.Application => {
  const app = express();

  // Security Headers
  app.use(helmet());

  // CORS Configuration
  app.use(
    cors({
      origin: [config.corsOrigin, 'http://localhost:5173', 'http://127.0.0.1:5173'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization']
    })
  );

  // Rate Limiting
  const limiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: 'Too Many Requests',
      message: 'Rate limit exceeded. Please try again later.'
    }
  });
  app.use('/api', limiter);

  // Body and Cookie Parsers
  app.use(express.json({ limit: '5mb' }));
  app.use(express.urlencoded({ extended: true, limit: '5mb' }));
  app.use(cookieParser());

  // Request Logging
  if (config.env !== 'test') {
    app.use(morgan('dev'));
  }

  // API Route Mounts
  app.use('/api/auth', authRoutes);
  app.use('/api/analyze', analysisRoutes);
  app.use('/api/batch', batchRoutes);
  app.use('/api/domains', domainRoutes);
  app.use('/api/reports', reportRoutes);
  app.use('/api/system', systemRoutes);
  app.use('/api/health', healthRoutes);

  // Fallback 404 for unknown endpoints
  app.use((req, res) => {
    res.status(404).json({
      error: 'Not Found',
      message: `The endpoint ${req.method} ${req.originalUrl} does not exist.`
    });
  });

  // Centralized Error Handler
  app.use(errorHandler);

  return app;
};
