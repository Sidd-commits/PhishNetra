import { MemoryCacheService } from '../src/services/cache/MemoryCacheService';

describe('Persistent Cache Layer (MemoryCacheService)', () => {
  let cache: MemoryCacheService;

  beforeEach(() => {
    cache = new MemoryCacheService(100, 10000);
  });

  afterEach(() => {
    cache.destroy();
  });

  it('should store and retrieve cached values correctly', async () => {
    await cache.set('test:key1', { message: 'hello world' }, 60);

    const val = await cache.get<{ message: string }>('test:key1');
    expect(val).toEqual({ message: 'hello world' });

    const exists = await cache.has('test:key1');
    expect(exists).toBe(true);
  });

  it('should return null for non-existent keys and record cache misses', async () => {
    const val = await cache.get('non:existent');
    expect(val).toBeNull();

    const stats = await cache.getStats();
    expect(stats.misses).toBe(1);
    expect(stats.hits).toBe(0);
  });

  it('should expire keys after TTL has elapsed', async () => {
    // Set 1 millisecond TTL
    await cache.set('temp:key', 'quick-expire', 0.05); // 50ms

    const before = await cache.get('temp:key');
    expect(before).toBe('quick-expire');

    // Wait for expiration
    await new Promise((resolve) => setTimeout(resolve, 80));

    const after = await cache.get('temp:key');
    expect(after).toBeNull();
  });

  it('should memoize expensive async computations with wrap()', async () => {
    let callCount = 0;
    const fetcher = async () => {
      callCount++;
      return { computed: 42 };
    };

    const first = await cache.wrap('wrap:key', fetcher, 60);
    expect(first).toEqual({ computed: 42 });
    expect(callCount).toBe(1);

    const second = await cache.wrap('wrap:key', fetcher, 60);
    expect(second).toEqual({ computed: 42 });
    expect(callCount).toBe(1); // Not called again!

    const stats = await cache.getStats();
    expect(stats.hits).toBe(1);
    expect(stats.misses).toBe(1);
  });

  it('should delete keys and clear all entries', async () => {
    await cache.set('k1', 'v1');
    await cache.set('k2', 'v2');

    await cache.del('k1');
    expect(await cache.get('k1')).toBeNull();
    expect(await cache.get('k2')).toBe('v2');

    await cache.clear();
    expect(await cache.get('k2')).toBeNull();
  });
});
