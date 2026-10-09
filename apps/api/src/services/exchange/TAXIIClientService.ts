import crypto from 'crypto';
import {
  TAXIIFeedConfig,
  TAXIISyncResult,
  CTIIndicator,
  CTIExchangeStats
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class TAXIIClientService {
  private feeds: Map<string, TAXIIFeedConfig> = new Map();
  private indicators: Map<string, CTIIndicator> = new Map();
  private syncHistory: TAXIISyncResult[] = [];

  constructor() {
    this.seedDefaultFeeds();
  }

  private seedDefaultFeeds(): void {
    const defaultFeeds: TAXIIFeedConfig[] = [
      {
        id: 'feed-cisa-ais',
        name: 'CISA Automated Indicator Sharing (AIS)',
        description: 'Federal US-CERT STIX/TAXII 2.1 feed distributing bidirectional phishing & credential harvesting IOCs.',
        apiRootUrl: 'https://taxii.cisa.gov/taxii2/',
        collectionId: 'cisa-phishing-indicators-v2',
        authType: 'BASIC',
        apiKey: 'demo-cisa-cert-key',
        tlpMarking: 'TLP:GREEN',
        syncIntervalMinutes: 60,
        isActive: true,
        autoBlockIndicators: true,
        lastSyncedAt: new Date(Date.now() - 3600000).toISOString(),
        totalIndicatorsIngested: 142
      },
      {
        id: 'feed-alienvault-otx',
        name: 'AlienVault OTX High-Confidence Phishing',
        description: 'Global community pulse intelligence tracking active spear-phishing campaigns and bulletproof domains.',
        apiRootUrl: 'https://otx.alienvault.com/taxii2/',
        collectionId: 'alienvault-spearphish-col',
        authType: 'API_KEY',
        apiKey: 'demo-otx-api-token-99x',
        tlpMarking: 'TLP:WHITE',
        syncIntervalMinutes: 30,
        isActive: true,
        autoBlockIndicators: true,
        lastSyncedAt: new Date(Date.now() - 1800000).toISOString(),
        totalIndicatorsIngested: 218
      },
      {
        id: 'feed-fs-isac',
        name: 'Financial Services ISAC (FS-ISAC) CTI Feed',
        description: 'High-fidelity banking and financial sector AiTM reverse proxy and quishing credential harvesting intelligence.',
        apiRootUrl: 'https://taxii.fsisac.com/api21/',
        collectionId: 'banking-credential-theft-col',
        authType: 'BEARER',
        apiKey: 'demo-bearer-fsisac-vault',
        tlpMarking: 'TLP:AMBER',
        syncIntervalMinutes: 120,
        isActive: true,
        autoBlockIndicators: true,
        lastSyncedAt: new Date(Date.now() - 7200000).toISOString(),
        totalIndicatorsIngested: 85
      }
    ];

    for (const feed of defaultFeeds) {
      this.feeds.set(feed.id, feed);
    }

    // Seed sample baseline indicators
    this.seedSampleIndicators();
  }

  private seedSampleIndicators(): void {
    const sampleData: CTIIndicator[] = [
      {
        id: 'ind-001',
        feedId: 'feed-cisa-ais',
        indicatorType: 'URL',
        indicatorValue: 'https://secure-login-microsoft-auth.xyz/verify',
        threatType: 'spear-phishing',
        confidence: 96,
        tlp: 'TLP:GREEN',
        stixId: 'indicator--a81e9f02-8641-4c74-9f7c-367d32bb5812',
        sourceFeedName: 'CISA Automated Indicator Sharing (AIS)',
        description: 'Active Microsoft 365 credential harvesting lure with stolen tenant branding.',
        validFrom: new Date(Date.now() - 86400000).toISOString(),
        killChainPhases: ['initial-access', 'credential-access'],
        tags: ['m365-harvest', 'evilginx2-lure', 'apt29-lookalike']
      },
      {
        id: 'ind-002',
        feedId: 'feed-alienvault-otx',
        indicatorType: 'DOMAIN',
        indicatorValue: 'account-update-paypal-verify.com',
        threatType: 'financial-phishing',
        confidence: 92,
        tlp: 'TLP:WHITE',
        stixId: 'indicator--b5919420-13f5-442e-8c90-95bca2249704',
        sourceFeedName: 'AlienVault OTX High-Confidence Phishing',
        description: 'PayPal credential theft form masquerading as 2FA identity challenge.',
        validFrom: new Date(Date.now() - 172800000).toISOString(),
        killChainPhases: ['credential-access'],
        tags: ['financial', 'paypal-spoof', 'fast-flux']
      },
      {
        id: 'ind-003',
        feedId: 'feed-fs-isac',
        indicatorType: 'IPV4',
        indicatorValue: '194.26.29.112',
        threatType: 'c2-proxy',
        confidence: 98,
        tlp: 'TLP:AMBER',
        stixId: 'indicator--c78d0221-50e3-47a1-9a74-d40bcf84192b',
        sourceFeedName: 'Financial Services ISAC (FS-ISAC) CTI Feed',
        description: 'AiTM reverse proxy relay server intercepting session cookies.',
        validFrom: new Date(Date.now() - 43200000).toISOString(),
        killChainPhases: ['defense-evasion', 'credential-access'],
        tags: ['aitm-reverse-proxy', 'bulletproof-host', 'session-hijack']
      }
    ];

    for (const ind of sampleData) {
      this.indicators.set(ind.id, ind);
    }
  }

  public listFeeds(): TAXIIFeedConfig[] {
    return Array.from(this.feeds.values());
  }

  public getFeed(feedId: string): TAXIIFeedConfig | undefined {
    return this.feeds.get(feedId);
  }

  public addFeed(config: Omit<TAXIIFeedConfig, 'id' | 'totalIndicatorsIngested'>): TAXIIFeedConfig {
    const id = `feed-${crypto.randomUUID().slice(0, 8)}`;
    const feed: TAXIIFeedConfig = {
      ...config,
      id,
      totalIndicatorsIngested: 0,
      lastSyncedAt: undefined
    };

    this.feeds.set(id, feed);

    auditLogService.log({
      actor: 'SOC Threat Intel Lead',
      action: 'CTI_TAXII_FEED_REGISTERED',
      category: 'THREAT_FEED',
      details: JSON.stringify({ feedId: id, name: feed.name, apiRoot: feed.apiRootUrl }),
      severity: 'INFO'
    });

    return feed;
  }

  public updateFeedStatus(feedId: string, isActive: boolean): TAXIIFeedConfig {
    const feed = this.feeds.get(feedId);
    if (!feed) {
      throw new Error(`TAXII Feed ${feedId} not found.`);
    }

    feed.isActive = isActive;
    this.feeds.set(feedId, feed);
    return feed;
  }

  public async syncFeed(feedId: string): Promise<TAXIISyncResult> {
    const feed = this.feeds.get(feedId);
    if (!feed) {
      throw new Error(`TAXII Feed ${feedId} not found.`);
    }

    const syncId = `sync-${crypto.randomUUID().slice(0, 8)}`;
    const now = new Date().toISOString();

    // Generate synthesized new STIX 2.1 indicators from TAXII Collection
    const simulatedFreshCount = Math.floor(Math.random() * 5) + 3;
    const ingested: CTIIndicator[] = [];
    let highConfidenceCount = 0;

    const sampleDomains = [
      'apple-id-verify-auth.co',
      'chase-online-secure-auth.net',
      'google-workspace-recovery-portal.info',
      'wellsfargo-mfa-security.top',
      'okta-sso-gateway-reauth.org'
    ];

    for (let i = 0; i < simulatedFreshCount; i++) {
      const domain = sampleDomains[i % sampleDomains.length];
      const indicatorId = `ind-${crypto.randomUUID().slice(0, 8)}`;
      const conf = Math.floor(Math.random() * 20) + 80;
      if (conf >= 90) highConfidenceCount++;

      const indicator: CTIIndicator = {
        id: indicatorId,
        feedId: feed.id,
        indicatorType: i % 2 === 0 ? 'DOMAIN' : 'URL',
        indicatorValue: i % 2 === 0 ? domain : `https://${domain}/login/checkpoint`,
        threatType: 'spear-phishing',
        confidence: conf,
        tlp: feed.tlpMarking,
        stixId: `indicator--${crypto.randomUUID()}`,
        sourceFeedName: feed.name,
        description: `Automated STIX 2.1 ingestion from ${feed.name} collection ${feed.collectionId}`,
        validFrom: now,
        validUntil: new Date(Date.now() + 30 * 86400000).toISOString(),
        killChainPhases: ['initial-access', 'credential-access'],
        tags: ['taxii21-sync', 'automated-ingest', 'cisa-stix']
      };

      this.indicators.set(indicator.id, indicator);
      ingested.push(indicator);
    }

    feed.lastSyncedAt = now;
    feed.totalIndicatorsIngested += ingested.length;
    this.feeds.set(feedId, feed);

    const result: TAXIISyncResult = {
      syncId,
      feedId: feed.id,
      feedName: feed.name,
      syncedAt: now,
      indicatorsIngested: ingested.length,
      duplicatesSkipped: 1,
      highConfidenceThreats: highConfidenceCount,
      status: 'SUCCESS',
      sampleIndicators: ingested
    };

    this.syncHistory.unshift(result);
    if (this.syncHistory.length > 50) this.syncHistory.pop();

    auditLogService.log({
      actor: 'CTI TAXII Sync Worker',
      action: 'CTI_TAXII_FEED_SYNCHRONIZED',
      category: 'THREAT_FEED',
      details: JSON.stringify({
        feedId: feed.id,
        feedName: feed.name,
        ingested: ingested.length,
        highConfidence: highConfidenceCount
      }),
      severity: 'INFO'
    });

    return result;
  }

  public listIndicators(filter?: {
    indicatorType?: string;
    tlp?: string;
    feedId?: string;
    limit?: number;
  }): CTIIndicator[] {
    let all = Array.from(this.indicators.values());

    if (filter?.indicatorType) {
      all = all.filter(i => i.indicatorType === filter.indicatorType);
    }
    if (filter?.tlp) {
      all = all.filter(i => i.tlp === filter.tlp);
    }
    if (filter?.feedId) {
      all = all.filter(i => i.feedId === filter.feedId);
    }

    const limit = filter?.limit || 100;
    return all.slice(0, limit);
  }

  public getSyncHistory(): TAXIISyncResult[] {
    return this.syncHistory;
  }

  public getExchangeStats(): CTIExchangeStats {
    const totalFeeds = this.feeds.size;
    let activeFeeds = 0;
    for (const feed of this.feeds.values()) {
      if (feed.isActive) activeFeeds++;
    }

    const totalIndicators = this.indicators.size;
    const indicatorsByType: Record<string, number> = {};
    const indicatorsByTlp: Record<string, number> = {};

    for (const ind of this.indicators.values()) {
      indicatorsByType[ind.indicatorType] = (indicatorsByType[ind.indicatorType] || 0) + 1;
      indicatorsByTlp[ind.tlp] = (indicatorsByTlp[ind.tlp] || 0) + 1;
    }

    const latestSync = this.syncHistory[0]?.syncedAt;

    return {
      totalFeeds,
      activeFeeds,
      totalIndicators,
      lastSyncTimestamp: latestSync,
      indicatorsByType,
      indicatorsByTlp
    };
  }
}

export const taxiiClientService = new TAXIIClientService();
