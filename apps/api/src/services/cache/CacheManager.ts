import { ICacheService, CacheStats } from './types';
import { MemoryCacheService } from './MemoryCacheService';
import { RedisCacheService } from './RedisCacheService';

export class CacheManager {
  private static instance: CacheManager;
  private cache: ICacheService;

  private constructor() {
    const redisUrl = process.env.REDIS_URL;
    if (redisUrl && redisUrl.trim().length > 0) {
      this.cache = new RedisCacheService(redisUrl);
    } else {
      this.cache = new MemoryCacheService(20000);
    }
  }

  public static getInstance(): CacheManager {
    if (!CacheManager.instance) {
      CacheManager.instance = new CacheManager();
    }
    return CacheManager.instance;
  }

  public getCache(): ICacheService {
    return this.cache;
  }

  public setCache(customCache: ICacheService): void {
    this.cache = customCache;
  }

  // Predefined TTL helpers for specific intelligence layers
  public static TTL = {
    RDAP_DOMAIN: 86400, // 24 hours
    DNS_RECORDS: 3600,  // 1 hour
    TLS_CERT: 7200,     // 2 hours
    REPUTATION: 900,    // 15 minutes
    URL_ANALYSIS: 600,  // 10 minutes
    PAGE_ANALYSIS: 600  // 10 minutes
  };

  public async getStats(): Promise<CacheStats> {
    return this.cache.getStats();
  }
}

export const cache = CacheManager.getInstance().getCache();
