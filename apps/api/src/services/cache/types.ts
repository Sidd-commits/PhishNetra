export interface CacheStats {
  hits: number;
  misses: number;
  keysCount: number;
  memoryUsageMb: number;
  hitRatio: number;
  driver: 'memory' | 'redis';
}

export interface ICacheService {
  readonly driver: 'memory' | 'redis';
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttlSeconds?: number): Promise<void>;
  del(key: string): Promise<void>;
  has(key: string): Promise<boolean>;
  getStats(): Promise<CacheStats>;
  clear(): Promise<void>;
  wrap<T>(key: string, fn: () => Promise<T>, ttlSeconds?: number): Promise<T>;
}
