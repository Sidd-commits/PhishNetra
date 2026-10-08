import { Router, Request, Response } from 'express';
import { siemExportEngine } from '../services/siem/SIEMExportEngine';
import { prisma } from '../db/prisma';
import { CampaignClusteringEngine } from '../services/graph/CampaignClusteringEngine';
import { SIEMExportRequestSchema, SIEMFormatSchema, ThreatCampaign, AnalysisResponse } from '@phishnetra/shared';

const router = Router();

/**
 * POST /api/siem/export
 * Formats threat analyses & campaigns into CEF, LEEF, Syslog, Sentinel, or Splunk HEC
 */
router.post('/export', async (req: Request, res: Response, next) => {
  try {
    const payload = SIEMExportRequestSchema.parse(req.body);
    
    // Fetch analyses from DB
    let dbAnalyses: any[] = [];
    if (payload.analysisIds && payload.analysisIds.length > 0) {
      dbAnalyses = await prisma.analysis.findMany({
        where: { id: { in: payload.analysisIds } },
        include: { evidence: true },
        take: 100
      });
    } else {
      dbAnalyses = await prisma.analysis.findMany({
        where: { verdict: { in: ['PHISHING', 'SUSPICIOUS'] } },
        include: { evidence: true },
        orderBy: { createdAt: 'desc' },
        take: 20
      });
    }

    // Convert Prisma models to AnalysisResponse shape
    const formattedAnalyses: AnalysisResponse[] = dbAnalyses.map(a => ({
      analysisId: a.id,
      url: a.url,
      normalizedUrl: a.normalizedUrl,
      verdict: a.verdict as any,
      riskScore: a.riskScore,
      riskLevel: a.riskLevel as any,
      confidence: a.confidence,
      mlProbability: a.mlProbability,
      evidence: (a.evidence || []).map((e: any) => ({
        layer: (e.layer || 'URL') as any,
        featureKey: e.featureKey || 'indicator',
        featureValue: e.featureValue || '',
        severity: (e.severity || 'HIGH') as any,
        title: e.description || e.featureKey,
        description: e.description || '',
        contribution: e.contribution || 10,
        source: e.source || 'Engine',
        confidence: e.confidence || 0.95
      })),
      summary: a.summary || '',
      createdAt: a.createdAt.toISOString()
    }));

    // Fetch campaigns
    const allCampaigns: ThreatCampaign[] = await CampaignClusteringEngine.listCampaigns();
    const targetCampaigns = payload.campaignIds
      ? allCampaigns.filter((c: ThreatCampaign) => payload.campaignIds?.includes(c.id))
      : allCampaigns.slice(0, 5);

    const exportResult = siemExportEngine.exportEvents(
      payload.format,
      formattedAnalyses,
      targetCampaigns
    );

    res.json({
      success: true,
      data: exportResult
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/siem/feed
 * Live SIEM stream feed
 */
router.get('/feed', async (req: Request, res: Response, next) => {
  try {
    const rawFormat = (req.query.format as string) || 'CEF';
    const format = SIEMFormatSchema.catch('CEF').parse(rawFormat);

    const latestAnalyses = await prisma.analysis.findMany({
      where: { verdict: { in: ['PHISHING', 'SUSPICIOUS'] } },
      include: { evidence: true },
      orderBy: { createdAt: 'desc' },
      take: 25
    });

    const formattedAnalyses: AnalysisResponse[] = latestAnalyses.map(a => ({
      analysisId: a.id,
      url: a.url,
      normalizedUrl: a.normalizedUrl,
      verdict: a.verdict as any,
      riskScore: a.riskScore,
      riskLevel: a.riskLevel as any,
      confidence: a.confidence,
      mlProbability: a.mlProbability,
      evidence: (a.evidence || []).map((e: any) => ({
        layer: (e.layer || 'URL') as any,
        featureKey: e.featureKey || 'indicator',
        featureValue: e.featureValue || '',
        severity: (e.severity || 'HIGH') as any,
        title: e.description || e.featureKey,
        description: e.description || '',
        contribution: e.contribution || 10,
        source: e.source || 'Engine',
        confidence: e.confidence || 0.95
      })),
      summary: a.summary || '',
      createdAt: a.createdAt.toISOString()
    }));

    const allCampaigns = await CampaignClusteringEngine.listCampaigns();
    const campaigns = allCampaigns.slice(0, 3);
    const exportResult = siemExportEngine.exportEvents(format, formattedAnalyses, campaigns);

    res.setHeader('Content-Type', exportResult.contentType);
    res.send(exportResult.formattedOutput);
  } catch (error) {
    next(error);
  }
});

export default router;
