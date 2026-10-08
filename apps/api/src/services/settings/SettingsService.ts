import crypto from 'crypto';
import {
  SystemConfig,
  UpdateSystemConfigRequest,
  ApiKeyItem,
  CreateApiKeyRequest,
  CreateApiKeyResponse
} from '@phishnetra/shared';

export class SettingsService {
  private config: SystemConfig;
  private apiKeys: Map<string, { apiKey: ApiKeyItem; hashedSecret: string }> = new Map();

  constructor() {
    this.config = this.getDefaultConfig();
    this.seedDefaultApiKeys();
  }

  private getDefaultConfig(): SystemConfig {
    return {
      weights: {
        url: 0.15,
        domain: 0.10,
        dns: 0.08,
        tls: 0.07,
        reputation: 0.20,
        ml: 0.15,
        content: 0.15,
        brand: 0.10
      },
      thresholds: {
        safeMax: 35,
        suspiciousMax: 70
      },
      providers: {
        urlhausEnabled: true,
        phishTankEnabled: true,
        virusTotalEnabled: false
      },
      whitelistedDomains: [
        'google.com',
        'microsoft.com',
        'github.com',
        'paypal.com',
        'apple.com',
        'amazon.com'
      ],
      autoRemediateCritical: false,
      feedSyncIntervalMinutes: 60,
      updatedAt: new Date().toISOString(),
      updatedBy: 'system'
    };
  }

  private seedDefaultApiKeys() {
    const defaultKeyId = 'key_default_soc_analyst';
    const rawSecret = 'phish_live_8f3a9e120bc74d83a19ef47b38d01129';
    const hashedSecret = crypto.createHash('sha256').update(rawSecret).digest('hex');

    const apiKey: ApiKeyItem = {
      id: defaultKeyId,
      name: 'SOC Automation Service Token',
      keyPrefix: 'phish_live_8f3a...',
      role: 'ANALYST',
      createdAt: new Date().toISOString(),
      lastUsedAt: new Date().toISOString(),
      expiresAt: null,
      status: 'ACTIVE'
    };

    this.apiKeys.set(defaultKeyId, { apiKey, hashedSecret });
  }

  public getConfig(): SystemConfig {
    return { ...this.config };
  }

  public updateConfig(req: UpdateSystemConfigRequest, actor = 'admin'): SystemConfig {
    if (req.weights) {
      this.config.weights = { ...this.config.weights, ...req.weights };
    }
    if (req.thresholds) {
      this.config.thresholds = { ...this.config.thresholds, ...req.thresholds };
    }
    if (req.providers) {
      this.config.providers = { ...this.config.providers, ...req.providers };
    }
    if (req.whitelistedDomains) {
      this.config.whitelistedDomains = [...new Set(req.whitelistedDomains.map(d => d.toLowerCase().trim()))];
    }
    if (req.autoRemediateCritical !== undefined) {
      this.config.autoRemediateCritical = req.autoRemediateCritical;
    }
    if (req.feedSyncIntervalMinutes !== undefined) {
      this.config.feedSyncIntervalMinutes = req.feedSyncIntervalMinutes;
    }

    this.config.updatedAt = new Date().toISOString();
    this.config.updatedBy = actor;

    return this.getConfig();
  }

  public resetToDefaults(actor = 'admin'): SystemConfig {
    this.config = this.getDefaultConfig();
    this.config.updatedBy = actor;
    return this.getConfig();
  }

  public listApiKeys(): ApiKeyItem[] {
    return Array.from(this.apiKeys.values()).map(k => k.apiKey);
  }

  public createApiKey(req: CreateApiKeyRequest): CreateApiKeyResponse {
    const id = `key_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const randomBytes = crypto.randomBytes(16).toString('hex');
    const secretToken = `phish_live_${randomBytes}`;
    const keyPrefix = `${secretToken.substring(0, 15)}...`;
    const hashedSecret = crypto.createHash('sha256').update(secretToken).digest('hex');

    const expiresAt = req.expiresInDays
      ? new Date(Date.now() + req.expiresInDays * 24 * 60 * 60 * 1000).toISOString()
      : null;

    const apiKey: ApiKeyItem = {
      id,
      name: req.name,
      keyPrefix,
      role: req.role || 'ANALYST',
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
      expiresAt,
      status: 'ACTIVE'
    };

    this.apiKeys.set(id, { apiKey, hashedSecret });

    return {
      apiKey,
      secretToken
    };
  }

  public revokeApiKey(id: string): boolean {
    const entry = this.apiKeys.get(id);
    if (!entry) return false;
    entry.apiKey.status = 'REVOKED';
    return true;
  }

  public validateApiKey(rawSecret: string): ApiKeyItem | null {
    const hashed = crypto.createHash('sha256').update(rawSecret).digest('hex');
    for (const entry of this.apiKeys.values()) {
      if (entry.hashedSecret === hashed && entry.apiKey.status === 'ACTIVE') {
        if (entry.apiKey.expiresAt && new Date(entry.apiKey.expiresAt).getTime() < Date.now()) {
          entry.apiKey.status = 'REVOKED';
          return null;
        }
        entry.apiKey.lastUsedAt = new Date().toISOString();
        return entry.apiKey;
      }
    }
    return null;
  }

  public isWhitelisted(domain: string): boolean {
    const cleanDomain = domain.toLowerCase().trim();
    return this.config.whitelistedDomains.some(w => cleanDomain === w || cleanDomain.endsWith(`.${w}`));
  }
}

export const settingsService = new SettingsService();
