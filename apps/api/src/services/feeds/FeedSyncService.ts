import {
  ThreatFeedStatus,
  ThreatFeedSyncResult,
  ThreatFeedSource
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class FeedSyncService {
  private feeds: Map<ThreatFeedSource, ThreatFeedStatus> = new Map();
  private isSyncing = false;

  constructor() {
    this.seedDefaultFeeds();
  }

  private seedDefaultFeeds() {
    const defaultFeeds: ThreatFeedStatus[] = [
      {
        id: 'feed_urlhaus',
        name: 'abuse.ch URLhaus Real-Time Phish/Malware Feed',
        source: 'URLHAUS',
        enabled: true,
        iocCount: 1420,
        lastSyncStatus: 'SUCCESS',
        lastSyncAt: new Date(Date.now() - 3600000 * 2).toISOString(),
        errorMessage: null
      },
      {
        id: 'feed_openphish',
        name: 'OpenPhish Global Threat Intelligence Feed',
        source: 'OPENPHISH',
        enabled: true,
        iocCount: 890,
        lastSyncStatus: 'SUCCESS',
        lastSyncAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        errorMessage: null
      },
      {
        id: 'feed_phishtank',
        name: 'PhishTank Verified Community Feed',
        source: 'PHISHTANK',
        enabled: true,
        iocCount: 2150,
        lastSyncStatus: 'SUCCESS',
        lastSyncAt: new Date(Date.now() - 3600000 * 6).toISOString(),
        errorMessage: null
      },
      {
        id: 'feed_cisa',
        name: 'CISA Known Exploited Vulnerabilities Catalog',
        source: 'CISA_KEV',
        enabled: false,
        iocCount: 320,
        lastSyncStatus: 'NEVER',
        lastSyncAt: null,
        errorMessage: null
      }
    ];

    for (const f of defaultFeeds) {
      this.feeds.set(f.source, f);
    }
  }

  public listFeeds(): ThreatFeedStatus[] {
    return Array.from(this.feeds.values());
  }

  public toggleFeed(source: ThreatFeedSource, enabled: boolean): ThreatFeedStatus | null {
    const feed = this.feeds.get(source);
    if (!feed) return null;
    feed.enabled = enabled;
    auditLogService.log({
      actor: 'system',
      action: enabled ? 'THREAT_FEED_ENABLED' : 'THREAT_FEED_DISABLED',
      category: 'THREAT_FEED',
      severity: 'INFO',
      target: source,
      details: `Threat feed ${feed.name} status updated to ${enabled ? 'ENABLED' : 'DISABLED'}`
    });
    return feed;
  }

  public async syncFeed(source: ThreatFeedSource, actor = 'admin'): Promise<ThreatFeedSyncResult> {
    const feed = this.feeds.get(source);
    if (!feed) {
      throw new Error(`Unknown threat feed source: ${source}`);
    }

    const startTime = Date.now();
    feed.lastSyncStatus = 'RUNNING';

    // Simulate realistic threat intelligence synchronization & deduplication
    await new Promise(r => setTimeout(r, 400));

    const simulatedAdded = Math.floor(Math.random() * 45) + 10;
    const simulatedDups = Math.floor(Math.random() * 80) + 20;
    const totalFetched = simulatedAdded + simulatedDups;

    feed.iocCount += simulatedAdded;
    feed.lastSyncStatus = 'SUCCESS';
    feed.lastSyncAt = new Date().toISOString();
    feed.errorMessage = null;

    const durationMs = Date.now() - startTime;

    const result: ThreatFeedSyncResult = {
      source,
      syncDurationMs: durationMs,
      totalFetched,
      newIocsAdded: simulatedAdded,
      duplicatesSkipped: simulatedDups,
      status: 'SUCCESS',
      syncedAt: new Date().toISOString()
    };

    auditLogService.log({
      actor,
      action: 'THREAT_FEED_SYNC_COMPLETED',
      category: 'THREAT_FEED',
      severity: 'INFO',
      target: source,
      details: `Synchronized ${feed.name}: Added ${simulatedAdded} new IOCs, ${simulatedDups} deduplicated in ${durationMs}ms`
    });

    return result;
  }

  public async syncAll(actor = 'system'): Promise<ThreatFeedSyncResult[]> {
    const results: ThreatFeedSyncResult[] = [];
    for (const feed of this.feeds.values()) {
      if (feed.enabled) {
        const res = await this.syncFeed(feed.source, actor);
        results.push(res);
      }
    }
    return results;
  }
}

export const feedSyncService = new FeedSyncService();
