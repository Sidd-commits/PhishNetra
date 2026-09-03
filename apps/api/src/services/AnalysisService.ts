import { prisma } from '../db/prisma';
import { mlClient } from './MLClientService';
import { riskEngine } from './RiskEngine';
import {
  AnalysisResponse,
  AnalysisSummary,
  ThreatVerdict,
  RiskLevel
} from '@phishnetra/shared';

export class AnalysisService {
  public normalizeUrl(rawUrl: string): string {
    let url = rawUrl.trim();
    const lower = url.toLowerCase();
    if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
      url = 'http://' + url;
    }
    try {
      const parsed = new URL(url);
      const scheme = parsed.protocol.toLowerCase();
      let host = parsed.host.toLowerCase();

      if (scheme === 'http:' && host.endsWith(':80')) {
        host = host.slice(0, -3);
      } else if (scheme === 'https:' && host.endsWith(':443')) {
        host = host.slice(0, -4);
      }

      const path = parsed.pathname || '/';
      const search = parsed.search || '';
      const hash = parsed.hash || '';

      return `${scheme}//${host}${path}${search}${hash}`;
    } catch {
      return rawUrl.trim();
    }
  }

  public async analyze(rawUrl: string, userId?: string): Promise<AnalysisResponse> {
    const normalizedUrl = this.normalizeUrl(rawUrl);

    const mlResult = await mlClient.predictURL(normalizedUrl);

    const riskResult = riskEngine.evaluate(
      mlResult.phishing_probability,
      mlResult.confidence,
      mlResult.features
    );

    const createdAnalysis = await prisma.analysis.create({
      data: {
        userId: userId || null,
        url: rawUrl.trim(),
        normalizedUrl,
        verdict: riskResult.verdict,
        riskScore: riskResult.riskScore,
        riskLevel: riskResult.riskLevel,
        confidence: riskResult.confidence,
        mlProbability: mlResult.phishing_probability,
        status: 'COMPLETED',
        evidence: {
          create: riskResult.evidence.map(e => ({
            featureKey: e.featureKey,
            featureValue: String(e.featureValue),
            severity: e.severity,
            description: e.description,
            contribution: e.contribution ?? 0.0
          }))
        }
      },
      include: {
        evidence: true
      }
    });

    return {
      analysisId: createdAnalysis.id,
      url: createdAnalysis.url,
      normalizedUrl: createdAnalysis.normalizedUrl,
      verdict: createdAnalysis.verdict as ThreatVerdict,
      riskScore: createdAnalysis.riskScore,
      riskLevel: createdAnalysis.riskLevel as RiskLevel,
      confidence: createdAnalysis.confidence,
      mlProbability: createdAnalysis.mlProbability,
      evidence: createdAnalysis.evidence.map(e => ({
        featureKey: e.featureKey,
        featureValue: e.featureValue,
        severity: e.severity as any,
        description: e.description,
        contribution: e.contribution ?? 0.0
      })),
      features: mlResult.features,
      createdAt: createdAnalysis.createdAt.toISOString()
    };
  }

  public async getUserAnalyses(userId: string, limit: number = 20, offset: number = 0): Promise<{ items: AnalysisSummary[]; total: number }> {
    const [items, total] = await Promise.all([
      prisma.analysis.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
        select: {
          id: true,
          url: true,
          verdict: true,
          riskScore: true,
          riskLevel: true,
          confidence: true,
          createdAt: true
        }
      }),
      prisma.analysis.count({
        where: { userId }
      })
    ]);

    return {
      items: items.map(item => ({
        id: item.id,
        url: item.url,
        verdict: item.verdict as ThreatVerdict,
        riskScore: item.riskScore,
        riskLevel: item.riskLevel as RiskLevel,
        confidence: item.confidence,
        createdAt: item.createdAt.toISOString()
      })),
      total
    };
  }

  public async getAnalysisById(analysisId: string): Promise<AnalysisResponse> {
    const record = await prisma.analysis.findUnique({
      where: { id: analysisId },
      include: { evidence: true }
    });

    if (!record) {
      const error: any = new Error('Analysis record not found');
      error.statusCode = 404;
      throw error;
    }

    return {
      analysisId: record.id,
      url: record.url,
      normalizedUrl: record.normalizedUrl,
      verdict: record.verdict as ThreatVerdict,
      riskScore: record.riskScore,
      riskLevel: record.riskLevel as RiskLevel,
      confidence: record.confidence,
      mlProbability: record.mlProbability,
      evidence: record.evidence.map(e => ({
        featureKey: e.featureKey,
        featureValue: e.featureValue,
        severity: e.severity as any,
        description: e.description,
        contribution: e.contribution ?? 0.0
      })),
      createdAt: record.createdAt.toISOString()
    };
  }
}

export const analysisService = new AnalysisService();
