/**
 * PhishNetra - Analysis Service Orchestrator (Multi-Layer Intelligence & Content Analysis)
 * Module: apps.api.src.services.AnalysisService
 * Milestone: 3
 */

import { prisma } from '../db/prisma';
import {
  AnalysisResponse,
  AnalysisSummary,
  EvidenceItem,
  LayerStatus,
  MultiLayerData,
  ThreatVerdict,
  RiskLevel,
  PageAnalysisResult
} from '@phishnetra/shared';
import { mlClientService } from './MLClientService';
import { pageAnalyzerClient } from './PageAnalyzerClient';
import { riskEngine } from './RiskEngine';
import { canonicalizeUrl } from './analysis/canonicalization';
import { urlLayer } from './analysis/urlLayer';
import { domainLayer } from './analysis/domainLayer';
import { dnsLayer } from './analysis/dnsLayer';
import { tlsLayer } from './analysis/tlsLayer';
import { reputationLayer } from './analysis/reputationLayer';
import { contentLayer } from './analysis/contentLayer';

export class AnalysisService {
  /**
   * Performs full Multi-Layer threat analysis on a target URL including isolated page inspection.
   */
  public async analyze(rawUrl: string, userId?: string, analyzePage = true): Promise<AnalysisResponse> {
    const startTime = Date.now();

    // 1. Canonicalize URL
    const canonical = canonicalizeUrl(rawUrl);
    const { canonicalUrl, hostname, protocol, port } = canonical;

    // 2. Query ML Inference Microservice (or local fallback)
    const mlResponse = await mlClientService.predictURL(canonicalUrl);

    // 3. Execute Intelligence Layers in parallel (Layers 1-5 + Isolated Page Inspection)
    const [urlRes, domainRes, dnsRes, tlsRes, repRes, pageRes] = await Promise.all([
      // Layer 1: URL Intelligence
      Promise.resolve(urlLayer.analyze(canonical, mlResponse.features)),

      // Layer 2: Domain Intelligence & RDAP
      domainLayer.analyze(hostname).catch(() => ({
        data: {
          status: 'FAILED' as LayerStatus,
          domain: hostname,
          registrableDomain: hostname,
          tld: '',
          subdomain: '',
          registrar: null,
          creationDate: null,
          expirationDate: null,
          domainAgeDays: null,
          domainAgeCategory: 'unknown' as const,
          isPrivacyProtected: false
        },
        evidence: []
      })),

      // Layer 3: DNS & IP Intelligence
      dnsLayer.analyze(hostname).catch(err => ({
        data: {
          status: 'FAILED' as LayerStatus,
          resolvedIps: [],
          ipv4Count: 0,
          ipv6Count: 0,
          nameservers: [],
          mxRecords: [],
          cnameRecords: [],
          txtRecords: [],
          hasMx: false,
          ipDetails: [],
          error: err.message
        },
        evidence: []
      })),

      // Layer 4: TLS Socket Intelligence
      tlsLayer.analyze(protocol, hostname, port).catch(err => ({
        data: {
          status: 'FAILED' as LayerStatus,
          hasTls: protocol.toLowerCase() === 'https:',
          certificateValid: false,
          certificateExpired: false,
          hostnameMatches: false,
          validFrom: null,
          validTo: null,
          daysUntilExpiry: null,
          issuer: null,
          subject: null,
          sans: [],
          tlsVersion: null,
          zeroTrustWarning: 'TLS inspection failed or timed out.',
          error: err.message
        },
        evidence: []
      })),

      // Layer 5: Reputation Intelligence
      reputationLayer.analyze(canonicalUrl, hostname).catch(() => ({
        data: {
          status: 'PARTIAL' as LayerStatus,
          providers: [],
          isListedMalicious: false,
          reputationScore: 0
        },
        evidence: []
      })),

      // Milestone 3: Isolated Page Inspection (SSRF-protected)
      analyzePage
        ? pageAnalyzerClient.analyzePage(canonicalUrl).catch(err => ({
            status: 'FAILED' as const,
            requestedUrl: canonicalUrl,
            finalUrl: canonicalUrl,
            redirectCount: 0,
            redirectChain: [],
            forms: [],
            iframes: [],
            scripts: [],
            keywords: [],
            brandFindings: [],
            urgencyScore: 0,
            contentRiskScore: 0,
            phishingProbability: 0,
            confidence: 0.5,
            error: err.message,
            blockReason: null,
            acquisitionTimeMs: 0
          }))
        : Promise.resolve({
            status: 'NOT_REQUESTED' as const,
            requestedUrl: canonicalUrl,
            finalUrl: canonicalUrl,
            redirectCount: 0,
            redirectChain: [],
            forms: [],
            iframes: [],
            scripts: [],
            keywords: [],
            brandFindings: [],
            urgencyScore: 0,
            contentRiskScore: 0,
            phishingProbability: 0,
            confidence: 1.0,
            error: null,
            blockReason: null,
            acquisitionTimeMs: 0
          })
    ]);

    // Layer 6: ML Layer Packaging
    const mlLayerData = {
      status: 'SUCCESS' as LayerStatus,
      phishingProbability: mlResponse.phishing_probability,
      confidence: mlResponse.confidence,
      predictedLabel: mlResponse.predicted_label,
      modelVersion: mlResponse.model_version,
      inferenceTimeMs: mlResponse.inference_time_ms
    };

    // Layer 7 & 8: Content & Brand Translation
    const contentRes = contentLayer.analyze(pageRes);

    // Aggregate Evidence across all layers
    const allLayerEvidences: EvidenceItem[] = [
      ...urlRes.evidence,
      ...domainRes.evidence,
      ...dnsRes.evidence,
      ...tlsRes.evidence,
      ...repRes.evidence,
      ...contentRes.evidence
    ];

    if (mlResponse.phishing_probability >= 0.70) {
      allLayerEvidences.push({
        layer: 'ML',
        featureKey: 'ml_phishing_classifier',
        featureValue: `${(mlResponse.phishing_probability * 100).toFixed(1)}%`,
        severity: 'CRITICAL',
        description: `Random Forest baseline ML classifier identified suspicious lexical patterns (${(mlResponse.phishing_probability * 100).toFixed(1)}% probability).`,
        contribution: 0.30,
        source: 'ML_RandomForest',
        confidence: mlResponse.confidence
      });
    } else if (mlResponse.phishing_probability >= 0.40) {
      allLayerEvidences.push({
        layer: 'ML',
        featureKey: 'ml_phishing_classifier',
        featureValue: `${(mlResponse.phishing_probability * 100).toFixed(1)}%`,
        severity: 'MEDIUM',
        description: `Machine learning classifier identified moderate threat probability (${(mlResponse.phishing_probability * 100).toFixed(1)}%).`,
        contribution: 0.15,
        source: 'ML_RandomForest',
        confidence: mlResponse.confidence
      });
    }

    // 4. Multi-Layer Risk Engine Synthesis
    const multiLayerResult = riskEngine.evaluateMultiLayer({
      urlLayer: urlRes.data,
      domainLayer: domainRes.data,
      dnsLayer: dnsRes.data,
      tlsLayer: tlsRes.data,
      reputationLayer: repRes.data,
      mlLayer: mlLayerData,
      pageLayer: pageRes,
      layerEvidences: allLayerEvidences
    });

    const layersData: MultiLayerData = {
      url: urlRes.data,
      domain: domainRes.data,
      dns: dnsRes.data,
      tls: tlsRes.data,
      reputation: repRes.data,
      ml: mlLayerData,
      page: pageRes
    };

    const layerStatuses: Record<string, LayerStatus> = {
      URL: urlRes.data.status,
      DOMAIN: domainRes.data.status,
      DNS: dnsRes.data.status,
      TLS: tlsRes.data.status,
      REPUTATION: repRes.data.status,
      ML: mlLayerData.status,
      CONTENT: contentRes.data.status,
      BRAND: contentRes.data.brandMismatch ? 'FAILED' : 'SUCCESS'
    };

    // 5. Persist Analysis Record & Evidence to Database
    let savedAnalysisId = `mock-${Date.now()}`;
    let createdAtIso = new Date().toISOString();

    try {
      const savedRecord = await prisma.analysis.create({
        data: {
          userId: userId || null,
          url: rawUrl,
          normalizedUrl: canonicalUrl,
          verdict: multiLayerResult.verdict,
          riskScore: multiLayerResult.riskScore,
          riskLevel: multiLayerResult.riskLevel,
          confidence: multiLayerResult.confidence,
          mlProbability: mlResponse.phishing_probability,
          status: 'COMPLETED',
          pageStatus: pageRes.status,
          layersJson: JSON.stringify(layersData),
          layerStatusesJson: JSON.stringify(layerStatuses),
          pageAnalysisJson: JSON.stringify(pageRes),
          summary: multiLayerResult.summary,
          evidence: {
            create: multiLayerResult.evidence.map(ev => ({
              layer: ev.layer,
              featureKey: ev.featureKey,
              featureValue: String(ev.featureValue),
              severity: ev.severity,
              description: ev.description,
              source: ev.source || 'RiskEngine',
              confidence: ev.confidence ?? 1.0,
              contribution: ev.contribution ?? 0.0
            }))
          }
        },
        include: {
          evidence: true
        }
      });

      savedAnalysisId = savedRecord.id;
      createdAtIso = savedRecord.createdAt.toISOString();
    } catch (dbErr: any) {
      console.warn(`[AnalysisService] Database write error: ${dbErr.message}. Serving in-memory result.`);
    }

    return {
      analysisId: savedAnalysisId,
      url: rawUrl,
      normalizedUrl: canonicalUrl,
      verdict: multiLayerResult.verdict,
      riskScore: multiLayerResult.riskScore,
      riskLevel: multiLayerResult.riskLevel,
      confidence: multiLayerResult.confidence,
      mlProbability: mlResponse.phishing_probability,
      layers: layersData,
      layerStatuses,
      pageAnalysis: pageRes,
      evidence: multiLayerResult.evidence,
      features: mlResponse.features,
      summary: multiLayerResult.summary,
      createdAt: createdAtIso
    };
  }

  /**
   * Retrieves user's previous analysis history with pagination.
   */
  public async getHistory(userId?: string, limit = 20, offset = 0): Promise<{ items: AnalysisSummary[]; total: number }> {
    try {
      const whereClause = userId ? { userId } : {};

      const [total, records] = await Promise.all([
        prisma.analysis.count({ where: whereClause }),
        prisma.analysis.findMany({
          where: whereClause,
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
            pageStatus: true,
            createdAt: true
          }
        })
      ]);

      const items: AnalysisSummary[] = records.map(r => ({
        id: r.id,
        url: r.url,
        verdict: r.verdict as ThreatVerdict,
        riskScore: r.riskScore,
        riskLevel: r.riskLevel as RiskLevel,
        confidence: r.confidence,
        pageStatus: (r.pageStatus || 'NOT_REQUESTED') as any,
        createdAt: r.createdAt.toISOString()
      }));

      return { items, total };
    } catch {
      return { items: [], total: 0 };
    }
  }

  /**
   * Retrieves full analysis report by ID including all layers, page analysis & evidence.
   */
  public async getById(id: string): Promise<AnalysisResponse | null> {
    try {
      const record = await prisma.analysis.findUnique({
        where: { id },
        include: {
          evidence: true
        }
      });

      if (!record) return null;

      let layers: MultiLayerData | undefined = undefined;
      let layerStatuses: Record<string, LayerStatus> | undefined = undefined;
      let pageAnalysis: PageAnalysisResult | undefined = undefined;

      if (record.layersJson) {
        try {
          layers = JSON.parse(record.layersJson);
        } catch {}
      }
      if (record.layerStatusesJson) {
        try {
          layerStatuses = JSON.parse(record.layerStatusesJson);
        } catch {}
      }
      if (record.pageAnalysisJson) {
        try {
          pageAnalysis = JSON.parse(record.pageAnalysisJson);
        } catch {}
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
        layers,
        layerStatuses,
        pageAnalysis,
        summary: record.summary || undefined,
        evidence: record.evidence.map(e => ({
          layer: (e.layer || 'URL') as any,
          featureKey: e.featureKey,
          featureValue: e.featureValue,
          severity: e.severity as any,
          description: e.description,
          source: e.source || 'RiskEngine',
          confidence: e.confidence ?? 1.0,
          contribution: e.contribution ?? 0.0
        })),
        createdAt: record.createdAt.toISOString()
      };
    } catch {
      return null;
    }
  }
}

export const analysisService = new AnalysisService();
