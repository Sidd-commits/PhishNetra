/**
 * PhishNetra - Multi-Layer Risk Engine (Zero-Trust Synthesis)
 * Module: apps.api.src.services.RiskEngine
 * Milestone: 3
 */

import {
  EvidenceItem,
  RiskLevel,
  ThreatVerdict,
  URLIntelligence,
  DomainIntelligence,
  DNSIntelligence,
  TLSIntelligence,
  ReputationIntelligence,
  MLIntelligence,
  PageAnalysisResult,
  LAYER_WEIGHTS,
  RISK_THRESHOLDS
} from '@phishnetra/shared';

import { settingsService } from './settings/SettingsService';

export interface MultiLayerEvaluationInput {
  urlLayer: URLIntelligence;
  domainLayer: DomainIntelligence;
  dnsLayer: DNSIntelligence;
  tlsLayer: TLSIntelligence;
  reputationLayer: ReputationIntelligence;
  mlLayer: MLIntelligence;
  pageLayer?: PageAnalysisResult;
  layerEvidences: EvidenceItem[];
}

export interface MultiLayerEvaluationResult {
  riskScore: number;
  riskLevel: RiskLevel;
  verdict: ThreatVerdict;
  confidence: number;
  evidence: EvidenceItem[];
  layerScores: Record<string, number>;
  summary: string;
}

export class RiskEngine {
  /**
   * Evaluates threat risk by synthesizing signals across all 8 intelligence layers:
   * (URL, Domain, DNS, TLS, Reputation, URL ML, Web Content, Brand Consistency).
   */
  public evaluateMultiLayer(input: MultiLayerEvaluationInput): MultiLayerEvaluationResult {
    const {
      urlLayer,
      domainLayer,
      dnsLayer,
      tlsLayer,
      reputationLayer,
      mlLayer,
      pageLayer,
      layerEvidences
    } = input;

    const currentConfig = settingsService.getConfig();
    const dynamicWeights: Record<string, number> = {
      URL: currentConfig.weights.url ?? LAYER_WEIGHTS.URL,
      DOMAIN: currentConfig.weights.domain ?? LAYER_WEIGHTS.DOMAIN,
      DNS: currentConfig.weights.dns ?? LAYER_WEIGHTS.DNS,
      TLS: currentConfig.weights.tls ?? LAYER_WEIGHTS.TLS,
      REPUTATION: currentConfig.weights.reputation ?? LAYER_WEIGHTS.REPUTATION,
      ML: currentConfig.weights.ml ?? LAYER_WEIGHTS.ML,
      CONTENT: currentConfig.weights.content ?? LAYER_WEIGHTS.CONTENT,
      BRAND: currentConfig.weights.brand ?? LAYER_WEIGHTS.BRAND
    };

    const layerScores: Record<string, number> = {
      URL: 0,
      DOMAIN: 0,
      DNS: 0,
      TLS: 0,
      REPUTATION: 0,
      ML: 0,
      CONTENT: 0,
      BRAND: 0
    };

    // 1. URL Layer Scoring (0 to 100)
    let urlScoreAcc = 0;
    if (urlLayer.features.has_ip_address === 1) urlScoreAcc += 40;
    if (urlLayer.hasUserInfo) urlScoreAcc += 30;
    if (urlLayer.isPunycode) urlScoreAcc += 35;
    if (urlLayer.isShortener) urlScoreAcc += 20;
    if (urlLayer.hasCustomPort) urlScoreAcc += 25;
    if (urlLayer.obfuscatedEncodings.length > 0) urlScoreAcc += 20;
    if (urlLayer.features.suspicious_keyword_count > 0) {
      urlScoreAcc += Math.min(35, urlLayer.features.suspicious_keyword_count * 12);
    }
    if (urlLayer.features.subdomain_count >= 3) urlScoreAcc += 20;
    if (urlLayer.features.tld_in_subdomain === 1) urlScoreAcc += 30;
    if (urlLayer.entropy > 4.5) urlScoreAcc += 15;
    layerScores.URL = Math.min(100, urlScoreAcc);

    // 2. Domain Layer Scoring (0 to 100)
    let domainScoreAcc = 0;
    if (domainLayer.domainAgeDays !== null && domainLayer.domainAgeDays !== undefined) {
      if (domainLayer.domainAgeDays < 30) {
        domainScoreAcc = 85;
      } else if (domainLayer.domainAgeDays < 90) {
        domainScoreAcc = 45;
      } else if (domainLayer.domainAgeDays < 365) {
        domainScoreAcc = 15;
      } else {
        domainScoreAcc = 0;
      }
    } else if (domainLayer.status === 'PARTIAL' || domainLayer.status === 'FAILED') {
      domainScoreAcc = 10;
    }
    layerScores.DOMAIN = Math.min(100, domainScoreAcc);

    // 3. DNS Layer Scoring (0 to 100)
    let dnsScoreAcc = 0;
    const hasPrivateIp = dnsLayer.resolvedIps.some(
      ip => ip === '127.0.0.1' || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.')
    );
    if (hasPrivateIp) {
      dnsScoreAcc = 100; // Critical SSRF indicator
    } else if (dnsLayer.error && dnsLayer.error.includes('NXDOMAIN')) {
      dnsScoreAcc = 60;
    } else if (dnsLayer.resolvedIps.length > 4) {
      dnsScoreAcc = 20;
    } else {
      dnsScoreAcc = 0;
    }
    layerScores.DNS = Math.min(100, dnsScoreAcc);

    // 4. TLS Layer Scoring (0 to 100)
    let tlsScoreAcc = 0;
    if (!tlsLayer.hasTls) {
      tlsScoreAcc = 25;
    } else {
      if (tlsLayer.certificateExpired) tlsScoreAcc += 70;
      if (!tlsLayer.hostnameMatches) tlsScoreAcc += 75;
      if (!tlsLayer.certificateValid && !tlsLayer.certificateExpired) tlsScoreAcc += 60;
      if (tlsLayer.daysUntilExpiry !== null && tlsLayer.daysUntilExpiry !== undefined && tlsLayer.daysUntilExpiry < 7) {
        tlsScoreAcc += 15;
      }
    }
    layerScores.TLS = Math.min(100, tlsScoreAcc);

    // 5. Reputation Layer Scoring (0 to 100)
    layerScores.REPUTATION = reputationLayer.reputationScore;

    // 6. ML Layer Scoring (0 to 100)
    layerScores.ML = Math.round(mlLayer.phishingProbability * 100 * 10) / 10;

    // 7 & 8. Web Content & Brand Consistency Scoring (Milestone 3)
    let hasBrandMismatch = false;
    let hasCrossOriginCredentialForm = false;
    let isSsrfBlocked = false;

    if (pageLayer) {
      if (pageLayer.status === 'BLOCKED') {
        isSsrfBlocked = true;
        layerScores.CONTENT = 90;
        layerScores.BRAND = 50;
      } else if (pageLayer.status === 'COMPLETED') {
        // Content Score (DOM, Forms, Scripts, Urgency)
        layerScores.CONTENT = pageLayer.contentRiskScore || 0;

        // Brand Consistency Score
        const brandFindings = pageLayer.brandFindings || [];
        const mismatchItem = brandFindings.find(b => b.isMismatch);
        if (mismatchItem) {
          hasBrandMismatch = true;
          layerScores.BRAND = Math.round(mismatchItem.confidence * 95);
        } else if (brandFindings.length > 0) {
          layerScores.BRAND = 0; // Verified authentic match
        } else {
          layerScores.BRAND = 5; // Neutral baseline
        }

        // Check cross-origin credential harvesting forms
        for (const form of pageLayer.forms || []) {
          if (form.hasPasswordField && (form.isCrossOrigin || form.isIpAction)) {
            hasCrossOriginCredentialForm = true;
            break;
          }
        }
      }
    }

    // --- Dynamic Weight Normalization (Tolerance to Missing / Unconfigured Layers) ---
    let activeWeightsSum = 0;
    const weightsToApply: Record<string, number> = {};

    for (const [layer, defaultWeight] of Object.entries(dynamicWeights)) {
      // If Reputation is completely unconfigured, exclude its weight
      if (layer === 'REPUTATION' && reputationLayer.providers.every(p => !p.isConfigured)) {
        continue;
      }
      // If Page analysis was not performed or skipped, exclude CONTENT & BRAND weights
      if ((layer === 'CONTENT' || layer === 'BRAND') && (!pageLayer || pageLayer.status === 'NOT_REQUESTED' || pageLayer.status === 'SKIPPED')) {
        continue;
      }
      weightsToApply[layer] = defaultWeight;
      activeWeightsSum += defaultWeight;
    }

    // Compute composite weighted risk score
    let compositeScore = 0;
    for (const [layer, weight] of Object.entries(weightsToApply)) {
      const normalizedWeight = weight / (activeWeightsSum || 1);
      compositeScore += (layerScores[layer] || 0) * normalizedWeight;
    }

    // --- Critical Override Rules ---
    // 1. Brand Impersonation Mismatch
    if (hasBrandMismatch) {
      compositeScore = Math.max(compositeScore, 82);
    }
    // 2. Cross-origin / Raw IP credential submission
    if (hasCrossOriginCredentialForm) {
      compositeScore = Math.max(compositeScore, 88);
    }
    // 3. Blacklisted Reputation Hit
    if (reputationLayer.isListedMalicious) {
      compositeScore = Math.max(compositeScore, 85);
    }
    // 4. SSRF Defense / Private IP Destination
    if (hasPrivateIp || isSsrfBlocked) {
      compositeScore = Math.max(compositeScore, 95);
    }

    const finalRiskScore = Math.round(Math.min(100, Math.max(0, compositeScore)) * 10) / 10;

    // Determine Verdict and Risk Level using configured thresholds
    const safeThreshold = currentConfig.thresholds.safeMax || RISK_THRESHOLDS.SAFE_MAX;
    const suspiciousThreshold = currentConfig.thresholds.suspiciousMax || RISK_THRESHOLDS.SUSPICIOUS_MAX;

    let verdict: ThreatVerdict = 'SAFE';
    let riskLevel: RiskLevel = 'LOW';

    if (finalRiskScore > RISK_THRESHOLDS.HIGH_MAX) {
      verdict = 'PHISHING';
      riskLevel = 'CRITICAL';
    } else if (finalRiskScore > suspiciousThreshold) {
      verdict = 'PHISHING';
      riskLevel = 'HIGH';
    } else if (finalRiskScore > safeThreshold) {
      verdict = 'SUSPICIOUS';
      riskLevel = 'MEDIUM';
    } else {
      verdict = 'SAFE';
      riskLevel = 'LOW';
    }

    // Confidence Synthesis across active layers
    let confidenceScore = (mlLayer.confidence * 0.3) +
      (urlLayer.status === 'SUCCESS' ? 0.12 : 0.05) +
      (domainLayer.status === 'SUCCESS' ? 0.12 : 0.05) +
      (dnsLayer.status === 'SUCCESS' ? 0.12 : 0.05) +
      (tlsLayer.status === 'SUCCESS' ? 0.12 : 0.05);

    if (pageLayer && pageLayer.status === 'COMPLETED') {
      confidenceScore += (pageLayer.confidence || 0.8) * 0.22;
    }

    const confidence = Math.min(1.0, Math.max(0.1, Math.round(confidenceScore * 100) / 100));

    // Deduplicate and sort evidence items by severity and contribution
    const severityRanks: Record<string, number> = {
      CRITICAL: 5,
      HIGH: 4,
      MEDIUM: 3,
      LOW: 2,
      INFO: 1
    };

    const sortedEvidence = [...layerEvidences].sort(
      (a, b) => (severityRanks[b.severity] || 0) - (severityRanks[a.severity] || 0)
    );

    // Generate explainable human-readable summary
    const summary = this.generateAnalysisSummary(
      verdict,
      riskLevel,
      finalRiskScore,
      confidence,
      hasBrandMismatch,
      hasCrossOriginCredentialForm,
      isSsrfBlocked,
      pageLayer,
      reputationLayer
    );

    return {
      riskScore: finalRiskScore,
      riskLevel,
      verdict,
      confidence,
      evidence: sortedEvidence,
      layerScores,
      summary
    };
  }

  /**
   * Synthesizes an explainable, human-readable threat summary from multi-layer evidence.
   */
  private generateAnalysisSummary(
    verdict: ThreatVerdict,
    riskLevel: RiskLevel,
    riskScore: number,
    confidence: number,
    hasBrandMismatch: boolean,
    hasCrossOriginCredentialForm: boolean,
    isSsrfBlocked: boolean,
    pageLayer?: PageAnalysisResult,
    reputationLayer?: ReputationIntelligence
  ): string {
    const highlights: string[] = [];

    if (isSsrfBlocked) {
      highlights.push('The destination target attempted to access prohibited private/loopback internal addresses and was blocked by Zero-Trust SSRF defense.');
    }

    if (hasBrandMismatch && pageLayer?.brandFindings) {
      const b = pageLayer.brandFindings.find(bf => bf.isMismatch);
      if (b) {
        highlights.push(`The webpage references '${b.claimedBrand}' authentication but is hosted on an unrelated domain ('${b.actualDomain}').`);
      }
    }

    if (hasCrossOriginCredentialForm) {
      highlights.push('A login form was detected transmitting sensitive credentials to an external or raw IP destination.');
    }

    if (pageLayer && pageLayer.redirectCount >= 2) {
      highlights.push(`The navigation traversed a chain of ${pageLayer.redirectCount} redirect hops.`);
    }

    if (reputationLayer?.isListedMalicious) {
      highlights.push('Reputation threat intelligence actively flags this destination as malicious.');
    }

    if (highlights.length === 0) {
      if (verdict === 'SAFE') {
        highlights.push('All structural, lexical, domain, and content signals align with normal legitimate website behavior.');
      } else {
        highlights.push('Moderate anomalous structural or lexical indicators detected across inspection layers.');
      }
    }

    return `PhishNetra Analysis Summary: Verdict is ${verdict} with ${riskLevel} threat risk (${riskScore}/100) and ${Math.round(confidence * 100)}% confidence.\n\n${highlights.join(' ')}`;
  }
}

export const riskEngine = new RiskEngine();
