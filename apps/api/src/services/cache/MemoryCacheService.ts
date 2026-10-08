import { ICacheService, CacheStats } from './types';

interface CacheEntry<T> {
  value: T;
  expiresAt: number | null; // null means no expiration
  createdAt: number;
}

export class MemoryCacheService implements ICacheService {
  readonly driver = 'memory' as const;
  private cache = new Map<string, CacheEntry<any>>();
  private hits = 0;
  private misses = 0;
  private cleanupInterval: NodeJS.Timeout | null = null;
  private maxItems: number;

  constructor(maxItems = 10000, cleanupIntervalMs = 60000) {
    this.maxItems = maxItems;
    // Auto purge expired entries periodically
    if (typeof setInterval !== 'undefined') {
      this.cleanupInterval = setInterval(() => {
        this.purgeExpired();
      }, cleanupIntervalMs);
      if (this.cleanupInterval.unref) {
        this.cleanupInterval.unref();
      }
    }
  }

  async get<T>(key: string): Promise<T | null> {
    const entry = this.cache.get(key);
    if (!entry) {
      this.misses++;
      return null;
    }

    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      this.misses++;
      return null;
    }

    this.hits++;
    return entry.value as T;
  }

  async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
    // Evict oldest item if capacity is reached
    if (this.cache.size >= this.maxItems && !this.cache.has(key)) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }

    const expiresAt = ttlSeconds && ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : null;
    this.cache.set(key, {
      value,
      expiresAt,
      createdAt: Date.now()
    });
  }

  async del(key: string): Promise<void> {
    this.cache.delete(key);
  }

  async has(key: string): Promise<boolean> {
    const entry = this.cache.get(key);
    if (!entry) return false;
    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return false;
    }
    return true;
  }

  async clear(): Promise<void> {
    this.cache.clear();
    this.hits = 0;
    this.misses = 0;
  }

  async getStats(): Promise<CacheStats> {
    const total = this.hits + this.misses;
    const hitRatio = total === 0 ? 0 : Number((this.hits / total).toFixed(4));
    const memoryUsageMb = Number((process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2));

    return {
      hits: this.hits,
      misses: this.misses,
      keysCount: this.cache.size,
      memoryUsageMb,
      hitRatio,
      driver: this.driver
    };
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

  private purgeExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (entry.expiresAt !== null && now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.cache.clear();
  }
}
