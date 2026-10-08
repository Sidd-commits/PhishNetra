import { AnalysisResponse } from '@phishnetra/shared';

export interface ExtensionSettings {
  apiUrl: string;
  dashboardUrl: string;
  autoScan: boolean;
  blockThreshold: number; // e.g. 75 or 80
  enableNotifications: boolean;
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  apiUrl: 'http://localhost:5000/api',
  dashboardUrl: 'http://localhost:5173',
  autoScan: true,
  blockThreshold: 75,
  enableNotifications: true
};

interface CacheItem {
  data: AnalysisResponse;
  expiresAt: number;
}

export class StorageService {
  /**
   * Retrieves extension settings from chrome.storage.local
   */
  public static async getSettings(): Promise<ExtensionSettings> {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return DEFAULT_SETTINGS;
    }

    return new Promise((resolve) => {
      chrome.storage.local.get(['settings'], (result) => {
        resolve({
          ...DEFAULT_SETTINGS,
          ...(result.settings || {})
        });
      });
    });
  }

  /**
   * Saves settings to chrome.storage.local
   */
  public static async saveSettings(settings: Partial<ExtensionSettings>): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;

    const current = await this.getSettings();
    const updated = { ...current, ...settings };

    return new Promise((resolve) => {
      chrome.storage.local.set({ settings: updated }, () => resolve());
    });
  }

  /**
   * Retrieves cached analysis result if valid (TTL: 15 mins)
   */
  public static async getCachedAnalysis(url: string): Promise<AnalysisResponse | null> {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return null;

    const key = `cache:${url}`;
    return new Promise((resolve) => {
      chrome.storage.local.get([key], (result) => {
        const item = result[key] as CacheItem | undefined;
        if (!item) {
          resolve(null);
          return;
        }

        if (Date.now() > item.expiresAt) {
          chrome.storage.local.remove(key);
          resolve(null);
          return;
        }

        resolve(item.data);
      });
    });
  }

  /**
   * Caches an analysis result with configurable TTL (default 15 minutes)
   */
  public static async setCachedAnalysis(url: string, data: AnalysisResponse, ttlMs = 15 * 60 * 1000): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;

    const key = `cache:${url}`;
    const item: CacheItem = {
      data,
      expiresAt: Date.now() + ttlMs
    };

    return new Promise((resolve) => {
      chrome.storage.local.set({ [key]: item }, () => resolve());
    });
  }

  /**
   * Whitelist Management
   */
  public static async getWhitelist(): Promise<string[]> {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return [];

    return new Promise((resolve) => {
      chrome.storage.local.get(['whitelist'], (result) => {
        resolve(result.whitelist || []);
      });
    });
  }

  public static async addToWhitelist(domain: string): Promise<void> {
    const clean = domain.toLowerCase().trim();
    const current = await this.getWhitelist();
    if (!current.includes(clean)) {
      const updated = [...current, clean];
      return new Promise((resolve) => {
        chrome.storage.local.set({ whitelist: updated }, () => resolve());
      });
    }
  }

  public static async removeFromWhitelist(domain: string): Promise<void> {
    const clean = domain.toLowerCase().trim();
    const current = await this.getWhitelist();
    const updated = current.filter((d) => d !== clean);
    return new Promise((resolve) => {
      chrome.storage.local.set({ whitelist: updated }, () => resolve());
    });
  }

  public static async isWhitelisted(domain: string): Promise<boolean> {
    const clean = domain.toLowerCase().trim();
    const list = await this.getWhitelist();
    return list.some((d) => clean === d || clean.endsWith('.' + d));
  }

  /**
   * Temporary User Session Bypasses (when user clicks "Continue Anyway" on interstitial)
   */
  public static async setTemporaryBypass(url: string): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.session) {
      if (typeof sessionStorage !== 'undefined') {
        sessionStorage.setItem(`bypass:${url}`, 'true');
      }
      return;
    }

    const key = `bypass:${url}`;
    return new Promise((resolve) => {
      chrome.storage.session.set({ [key]: true }, () => resolve());
    });
  }

  public static async hasTemporaryBypass(url: string): Promise<boolean> {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.session) {
      if (typeof sessionStorage !== 'undefined') {
        return sessionStorage.getItem(`bypass:${url}`) === 'true';
      }
      return false;
    }

    const key = `bypass:${url}`;
    return new Promise((resolve) => {
      chrome.storage.session.get([key], (result) => {
        resolve(result[key] === true);
      });
    });
  }
}
