import { StorageService, DEFAULT_SETTINGS } from '../src/utils/storage';

describe('StorageService', () => {
  const originalChrome = (global as any).chrome;

  beforeEach(() => {
    // Mock chrome.storage.local
    const store: Record<string, any> = {};
    (global as any).chrome = {
      storage: {
        local: {
          get: (keys: string[] | null, callback: (result: Record<string, any>) => void) => {
            if (!keys) {
              callback(store);
              return;
            }
            const res: Record<string, any> = {};
            for (const k of keys) {
              if (store[k] !== undefined) res[k] = store[k];
            }
            callback(res);
          },
          set: (items: Record<string, any>, callback: () => void) => {
            Object.assign(store, items);
            if (callback) callback();
          },
          remove: (keys: string | string[], callback?: () => void) => {
            const keyArr = Array.isArray(keys) ? keys : [keys];
            for (const k of keyArr) delete store[k];
            if (callback) callback();
          }
        },
        session: {
          get: (keys: string[], callback: (result: Record<string, any>) => void) => {
            const res: Record<string, any> = {};
            for (const k of keys) {
              if (store[k] !== undefined) res[k] = store[k];
            }
            callback(res);
          },
          set: (items: Record<string, any>, callback: () => void) => {
            Object.assign(store, items);
            if (callback) callback();
          }
        }
      }
    };
  });

  afterAll(() => {
    (global as any).chrome = originalChrome;
  });

  it('should return default settings initially', async () => {
    const settings = await StorageService.getSettings();
    expect(settings.apiUrl).toBe(DEFAULT_SETTINGS.apiUrl);
    expect(settings.blockThreshold).toBe(DEFAULT_SETTINGS.blockThreshold);
  });

  it('should save and update settings correctly', async () => {
    await StorageService.saveSettings({ blockThreshold: 85, autoScan: false });
    const updated = await StorageService.getSettings();
    expect(updated.blockThreshold).toBe(85);
    expect(updated.autoScan).toBe(false);
    expect(updated.apiUrl).toBe(DEFAULT_SETTINGS.apiUrl);
  });

  it('should manage whitelist domains correctly', async () => {
    expect(await StorageService.getWhitelist()).toEqual([]);
    await StorageService.addToWhitelist('internal.corp');
    await StorageService.addToWhitelist('safe.bank.com');

    expect(await StorageService.isWhitelisted('internal.corp')).toBe(true);
    expect(await StorageService.isWhitelisted('sub.internal.corp')).toBe(true);
    expect(await StorageService.isWhitelisted('attacker.com')).toBe(false);

    await StorageService.removeFromWhitelist('internal.corp');
    expect(await StorageService.isWhitelisted('internal.corp')).toBe(false);
  });

  it('should cache and retrieve analysis data within TTL', async () => {
    const mockAnalysis: any = {
      analysisId: 'mock-123',
      url: 'https://example.com',
      normalizedUrl: 'https://example.com',
      riskScore: 10,
      verdict: 'SAFE',
      riskLevel: 'LOW',
      confidence: 0.95,
      mlProbability: 0.05,
      evidence: [],
      createdAt: new Date().toISOString()
    };

    await StorageService.setCachedAnalysis('https://example.com', mockAnalysis, 10000);
    const cached = await StorageService.getCachedAnalysis('https://example.com');
    expect(cached).not.toBeNull();
    expect(cached?.riskScore).toBe(10);
    expect(cached?.verdict).toBe('SAFE');
  });

  it('should handle temporary session bypasses', async () => {
    expect(await StorageService.hasTemporaryBypass('https://warning.com')).toBe(false);
    await StorageService.setTemporaryBypass('https://warning.com');
    expect(await StorageService.hasTemporaryBypass('https://warning.com')).toBe(true);
  });
});
