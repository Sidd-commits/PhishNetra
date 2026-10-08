import { CacheManager } from './CacheManager';

export * from './types';
export * from './MemoryCacheService';
export * from './RedisCacheService';
export * from './CacheManager';

export const cacheManager = CacheManager.getInstance();
export const cacheService = cacheManager.getCache();
