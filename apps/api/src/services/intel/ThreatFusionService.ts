import {
  ThreatFusionEntry,
  BayesianDecayConfig,
  ThreatFusionScoreRequest
} from '@phishnetra/shared';
import crypto from 'crypto';

export class ThreatFusionService {
  private static decayConfig: BayesianDecayConfig = {
    defaultHalfLifeHours: 48,
    fastFluxIpHalfLifeHours: 24,
    domainHalfLifeHours: 168,
    decayFloorScore: 5
  };

  private static fusedStore: ThreatFusionEntry[] = [
    {
      id: 'fusion-1',
      iocValue: '185.220.101.5',
      iocType: 'IP',
      firstSeen: new Date(Date.now() - 36 * 3600 * 1000).toISOString(),
      lastSeen: new Date(Date.now() - 12 * 3600 * 1000).toISOString(),
      sourceFeeds: ['URLHAUS', 'OPENPHISH', 'HONEYPOT'],
      baseScore: 92,
      decayedScore: 78,
      halfLifeHours: 24,
      confidence: 0.95,
      status: 'ACTIVE'
    },
    {
      id: 'fusion-2',
      iocValue: 'secure-verify-paypal.xyz',
      iocType: 'DOMAIN',
      firstSeen: new Date(Date.now() - 72 * 3600 * 1000).toISOString(),
      lastSeen: new Date(Date.now() - 6 * 3600 * 1000).toISOString(),
      sourceFeeds: ['PHISHTANK', 'URLHAUS', 'CISA_KEV'],
      baseScore: 96,
      decayedScore: 89,
      halfLifeHours: 168,
      confidence: 0.98,
      status: 'ACTIVE'
    },
    {
      id: 'fusion-3',
      iocValue: '194.26.29.112',
      iocType: 'IP',
      firstSeen: new Date(Date.now() - 120 * 3600 * 1000).toISOString(),
      lastSeen: new Date(Date.now() - 96 * 3600 * 1000).toISOString(),
      sourceFeeds: ['OPENPHISH'],
      baseScore: 75,
      decayedScore: 18,
      halfLifeHours: 24,
      confidence: 0.82,
      status: 'DECAYED'
    }
  ];

  /**
   * Calculates exponential temporal Bayesian decay for an IOC
   */
  public static calculateDecayedScore(
    baseScore: number,
    hoursElapsed: number,
    halfLifeHours: number,
    floorScore: number = this.decayConfig.decayFloorScore
  ): number {
    if (hoursElapsed <= 0) return baseScore;
    const decayed = baseScore * Math.pow(0.5, hoursElapsed / halfLifeHours);
    return Math.max(floorScore, Math.round(decayed * 100) / 100);
  }

  /**
   * Evaluates or ingests a new IOC with multi-feed consensus and temporal decay
   */
  public static evaluateIOC(req: ThreatFusionScoreRequest): ThreatFusionEntry {
    const existing = this.fusedStore.find(
      e => e.iocValue.toLowerCase() === req.iocValue.toLowerCase() && e.iocType === req.iocType
    );

    const halfLife =
      req.customHalfLifeHours ||
      (req.iocType === 'IP'
        ? this.decayConfig.fastFluxIpHalfLifeHours
        : req.iocType === 'DOMAIN'
        ? this.decayConfig.domainHalfLifeHours
        : this.decayConfig.defaultHalfLifeHours);

    if (existing) {
      const elapsedHours = (Date.now() - new Date(existing.lastSeen).getTime()) / (3600 * 1000);
      existing.decayedScore = this.calculateDecayedScore(existing.baseScore, elapsedHours, halfLife);
      existing.status = existing.decayedScore > 30 ? 'ACTIVE' : 'DECAYED';
      return existing;
    }

    const feeds = req.sourceFeeds && req.sourceFeeds.length > 0 ? req.sourceFeeds : ['INTERNAL_ANALYTICS'];
    const baseScore = Math.min(100, 50 + feeds.length * 15);
    const confidence = Math.min(0.99, 0.6 + feeds.length * 0.1);
    const now = new Date().toISOString();

    const newEntry: ThreatFusionEntry = {
      id: `fusion-${crypto.randomBytes(4).toString('hex')}`,
      iocValue: req.iocValue.trim(),
      iocType: req.iocType,
      firstSeen: now,
      lastSeen: now,
      sourceFeeds: feeds,
      baseScore,
      decayedScore: baseScore,
      halfLifeHours: halfLife,
      confidence,
      status: 'ACTIVE'
    };

    this.fusedStore.unshift(newEntry);
    return newEntry;
  }

  public static listEntries(): ThreatFusionEntry[] {
    // Dynamically refresh decayed scores
    return this.fusedStore.map(entry => {
      const elapsedHours = (Date.now() - new Date(entry.lastSeen).getTime()) / (3600 * 1000);
      const decayed = this.calculateDecayedScore(entry.baseScore, elapsedHours, entry.halfLifeHours);
      return {
        ...entry,
        decayedScore: decayed,
        status: decayed > 30 ? 'ACTIVE' : 'DECAYED'
      };
    });
  }

  public static getDecayConfig(): BayesianDecayConfig {
    return this.decayConfig;
  }

  public static updateDecayConfig(updates: Partial<BayesianDecayConfig>): BayesianDecayConfig {
    this.decayConfig = { ...this.decayConfig, ...updates };
    return this.decayConfig;
  }
}
