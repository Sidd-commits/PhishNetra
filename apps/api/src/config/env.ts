import dotenv from 'dotenv';
import path from 'path';

// Load .env file from root or api workspace
dotenv.config({ path: path.resolve(process.cwd(), '../../.env') });
dotenv.config();

export const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '5000', 10),
  host: process.env.API_HOST || '0.0.0.0',
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  jwt: {
    secret: process.env.JWT_SECRET || 'phishnetra_dev_jwt_secret_key_change_in_production_32char_min',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  },
  databaseUrl: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/phishnetra?schema=public',
  mlService: {
    url: process.env.ML_SERVICE_URL || 'http://localhost:8000',
    timeoutMs: parseInt(process.env.ML_SERVICE_TIMEOUT_MS || '5000', 10)
  },
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 mins
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10)
  }
};
