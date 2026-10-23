import { prisma } from '../db/prisma';
import { DomainDossier, RiskLevel, AnalysisSummary } from '@phishnetra/shared';
import { DomainLayer } from './analysis/domainLayer';
import { DNSLayer } from './analysis/dnsLayer';
import { TyposquattingEngine } from './analysis/typosquatting';
import { cache, CacheManager } from './cache/CacheManager';
import { analysisService } from './AnalysisService';

export class DomainService {
  private domainLayer = new DomainLayer();
  private dnsLayer = new DNSLayer();

  /**
   * Retrieves comprehensive domain dossier including registration, DNS records,
   * typosquatting inspection, historical scan aggregates, and community reports.
   */
  public async getDomainDossier(domainName: string): Promise<DomainDossier> {
    const cleanDomain = domainName.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const cacheKey = `dossier:${cleanDomain}`;

    return cache.wrap(cacheKey, async () => {
      return this.buildDossier(cleanDomain);
    }, CacheManager.TTL.DNS_RECORDS);
  }

  private async buildDossier(cleanDomain: string): Promise<DomainDossier> {
    // 1. Fetch domain metadata & DNS records in parallel
    const [domainResult, dnsResult] = await Promise.all([
      this.domainLayer.analyze(cleanDomain),
      this.dnsLayer.analyze(cleanDomain)
    ]);

    // 2. Perform Typosquatting / Homoglyph inspection
    const typoScan = TyposquattingEngine.inspectDomain(cleanDomain);
    const generatedPermutations = TyposquattingEngine.generatePermutations(cleanDomain);
    const combinedTypos = [...typoScan.matches, ...generatedPermutations.slice(0, 5)];

    // 3. Query historical analyses for this domain from Prisma
    let pastAnalyses: any[] = [];
    let communityReportsCount = 0;

    try {
      pastAnalyses = await prisma.analysis.findMany({
        where: {
          OR: [
            { url: { contains: cleanDomain } },
            { normalizedUrl: { contains: cleanDomain } }
          ]
        },
        orderBy: { createdAt: 'desc' },
        take: 10
      });

      communityReportsCount = await prisma.communityReport.count({
        where: {
          domain: { equals: cleanDomain }
        }
      });
    } catch (err: any) {
      console.warn(`[DomainService] DB query failed (${err.message}). Continuing with empty history.`);
    }

    // Merge recent in-memory analyses for this domain if not already in DB records
    const inMemMatching = analysisService.getRecentByDomain(cleanDomain);
    for (const mem of inMemMatching) {
      if (!pastAnalyses.some(p => p.id === mem.analysisId)) {
        pastAnalyses.unshift({
          id: mem.analysisId,
          url: mem.url,
          verdict: mem.verdict,
          riskScore: mem.riskScore,
          confidence: mem.confidence,
          createdAt: new Date(mem.createdAt)
        });
      }
    }

    const totalScans = pastAnalyses.length;
    const phishingScans = pastAnalyses.filter((a) => a.verdict === 'PHISHING').length;

    // Calculate aggregated domain risk score
    let domainRiskScore = 15; // baseline low risk
    if (totalScans > 0) {
      const recentVerdict = pastAnalyses[0]?.verdict;
      const recentScore = Math.round(pastAnalyses[0]?.riskScore ?? 15);
      const phishingRatio = phishingScans / totalScans;

      if (recentVerdict === 'SAFE') {
        domainRiskScore = Math.min(100, Math.round(recentScore + phishingRatio * 10));
      } else if (recentVerdict === 'PHISHING' || phishingRatio > 0.5) {
        domainRiskScore = Math.min(100, Math.max(recentScore, 75));
      } else if (recentVerdict === 'SUSPICIOUS' || phishingRatio > 0.2) {
        domainRiskScore = Math.min(100, Math.max(recentScore, 45));
      } else {
        domainRiskScore = recentScore;
      }
    } else if (domainResult.data.domainAgeCategory === '< 30 days') {
      domainRiskScore = Math.max(domainRiskScore, 45);
    } else if (typoScan.isDirectImpersonation) {
      domainRiskScore = Math.max(domainRiskScore, 75);
    }

    let riskLevel: RiskLevel = 'LOW';
    if (domainRiskScore >= 80) riskLevel = 'CRITICAL';
    else if (domainRiskScore >= 60) riskLevel = 'HIGH';
    else if (domainRiskScore >= 30) riskLevel = 'MEDIUM';

    const recentAnalyses: AnalysisSummary[] = pastAnalyses.map((a) => ({
      id: a.id,
      url: a.url,
      verdict: a.verdict as any,
      riskScore: a.riskScore,
      riskLevel: a.riskLevel as any,
      confidence: a.confidence,
      createdAt: a.createdAt.toISOString()
    }));

    return {
      domain: cleanDomain,
      registrableDomain: domainResult.data.registrableDomain || cleanDomain,
      domainAgeDays: domainResult.data.domainAgeDays,
      ageCategory: domainResult.data.domainAgeCategory,
      registrar: domainResult.data.registrar,
      nameservers: dnsResult.data.nameservers || [],
      ipAddresses: dnsResult.data.resolvedIps || [],
      totalScans,
      phishingScans,
      riskScore: domainRiskScore,
      riskLevel,
      reputationStatus: domainResult.data.status === 'SUCCESS' ? 'HEALTHY' : 'UNVERIFIED',
      typosquattingAlerts: combinedTypos,
      recentAnalyses,
      communityReportsCount,
      createdAt: new Date().toISOString()
    };
  }

  /**
   * Generates typosquatting and homoglyph intelligence for any target domain or brand.
   */
  public analyzeTyposquatting(domainName: string) {
    const cleanDomain = domainName.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const scan = TyposquattingEngine.inspectDomain(cleanDomain);
    const permutations = TyposquattingEngine.generatePermutations(cleanDomain);

    return {
      ...scan,
      permutations
    };
  }
}

export const domainService = new DomainService();
