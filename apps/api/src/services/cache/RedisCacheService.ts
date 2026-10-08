import Redis from 'ioredis';
import { ICacheService, CacheStats } from './types';
import { MemoryCacheService } from './MemoryCacheService';

export class RedisCacheService implements ICacheService {
  readonly driver = 'redis' as const;
  private client: Redis | null = null;
  private fallbackMemory: MemoryCacheService;
  private isConnected = false;
  private hits = 0;
  private misses = 0;
  private keyPrefix: string;

  constructor(redisUrl?: string, keyPrefix = 'phishnetra:cache:') {
    this.keyPrefix = keyPrefix;
    this.fallbackMemory = new MemoryCacheService();

    const targetUrl = redisUrl || process.env.REDIS_URL || 'redis://127.0.0.1:6379';
    try {
      this.client = new Redis(targetUrl, {
        maxRetriesPerRequest: 1,
        connectTimeout: 2000,
        lazyConnect: true,
        enableOfflineQueue: false
      });

      this.client.on('connect', () => {
        this.isConnected = true;
        console.log('[RedisCacheService] Connected to Redis server.');
      });

      this.client.on('error', (err) => {
        if (this.isConnected) {
          console.warn(`[RedisCacheService] Redis error (${err.message}). Defaulting to memory cache.`);
        }
        this.isConnected = false;
      });

      this.client.connect().catch((_err) => {
        // Suppress initial connection failure, fallback cleanly
        this.isConnected = false;
      });
    } catch (_err) {
      this.isConnected = false;
    }
  }

  private prefixedKey(key: string): string {
    return `${this.keyPrefix}${key}`;
  }

  async get<T>(key: string): Promise<T | null> {
    if (!this.isConnected || !this.client) {
      return this.fallbackMemory.get<T>(key);
    }

    try {
      const data = await this.client.get(this.prefixedKey(key));
      if (!data) {
        this.misses++;
        return null;
      }
      this.hits++;
      return JSON.parse(data) as T;
    } catch {
      return this.fallbackMemory.get<T>(key);
    }
  }

  async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    if (!this.isConnected || !this.client) {
      return this.fallbackMemory.set<T>(key, value, ttlSeconds);
    }

    try {
      const serialized = JSON.stringify(value);
      if (ttlSeconds && ttlSeconds > 0) {
        await this.client.set(this.prefixedKey(key), serialized, 'EX', ttlSeconds);
      } else {
        await this.client.set(this.prefixedKey(key), serialized);
      }
    } catch {
      await this.fallbackMemory.set<T>(key, value, ttlSeconds);
    }
  }

  async del(key: string): Promise<void> {
    if (!this.isConnected || !this.client) {
      return this.fallbackMemory.del(key);
    }

    try {
      await this.client.del(this.prefixedKey(key));
    } catch {
      await this.fallbackMemory.del(key);
    }
  }

  async has(key: string): Promise<boolean> {
    if (!this.isConnected || !this.client) {
      return this.fallbackMemory.has(key);
    }

    try {
      const exists = await this.client.exists(this.prefixedKey(key));
      return exists === 1;
    } catch {
      return this.fallbackMemory.has(key);
    }
  }

  async clear(): Promise<void> {
    if (!this.isConnected || !this.client) {
      return this.fallbackMemory.clear();
    }

    try {
      const keys = await this.client.keys(`${this.keyPrefix}*`);
      if (keys.length > 0) {
        await this.client.del(...keys);
      }
      this.hits = 0;
      this.misses = 0;
    } catch {
      await this.fallbackMemory.clear();
    }
  }

  async getStats(): Promise<CacheStats> {
    if (!this.isConnected || !this.client) {
      return this.fallbackMemory.getStats();
    }

    try {
      const total = this.hits + this.misses;
      const hitRatio = total === 0 ? 0 : Number((this.hits / total).toFixed(4));
      const keys = await this.client.keys(`${this.keyPrefix}*`);
      const memoryUsageMb = Number((process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2));

      return {
        hits: this.hits,
        misses: this.misses,
        keysCount: keys.length,
        memoryUsageMb,
        hitRatio,
        driver: this.driver
      };
    } catch {
      return this.fallbackMemory.getStats();
    }
  }

  async wrap<T>(key: string, fn: () => Promise<T>, ttlSeconds = 300): Promise<T> {
    const cached = await this.get<T>(key);
    if (cached !== null) {
      return cached;
    }
    const fresh = await fn();
    await this.set(key, fresh, ttlSeconds);
    return fresh;
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      try {
        await this.client.quit();
      } catch {
        this.client.disconnect();
      }
    }
    this.fallbackMemory.destroy();
  }
}
