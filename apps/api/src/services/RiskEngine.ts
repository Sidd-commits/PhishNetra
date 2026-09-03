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
  LAYER_WEIGHTS,
  RISK_THRESHOLDS
} from '@phishnetra/shared';

export interface MultiLayerEvaluationInput {
  urlLayer: URLIntelligence;
  domainLayer: DomainIntelligence;
  dnsLayer: DNSIntelligence;
  tlsLayer: TLSIntelligence;
  reputationLayer: ReputationIntelligence;
  mlLayer: MLIntelligence;
  layerEvidences: EvidenceItem[];
}

export interface MultiLayerEvaluationResult {
  riskScore: number;
  riskLevel: RiskLevel;
  verdict: ThreatVerdict;
  confidence: number;
  evidence: EvidenceItem[];
  layerScores: Record<string, number>;
}

export class RiskEngine {
  /**
   * Evaluates threat risk by synthesizing signals across all 5+ intelligence layers.
   */
  public evaluateMultiLayer(input: MultiLayerEvaluationInput): MultiLayerEvaluationResult {
    const { urlLayer, domainLayer, dnsLayer, tlsLayer, reputationLayer, mlLayer, layerEvidences } = input;

    const layerScores: Record<string, number> = {
      URL: 0,
      DOMAIN: 0,
      DNS: 0,
      TLS: 0,
      REPUTATION: 0,
      ML: 0
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
      domainScoreAcc = 10; // Neutral slight ambiguity
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
      tlsScoreAcc = 25; // Insecure plaintext HTTP
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

    // --- Dynamic Weight Normalization (Tolerance to Missing / Unconfigured Layers) ---
    let activeWeightsSum = 0;
    const weightsToApply: Record<string, number> = {};

    for (const [layer, defaultWeight] of Object.entries(LAYER_WEIGHTS)) {
      // If a layer is completely skipped/not configured, exclude its weight so it doesn't skew score
      if (layer === 'REPUTATION' && reputationLayer.providers.every(p => !p.isConfigured)) {
        continue;
      }
      weightsToApply[layer] = defaultWeight;
      activeWeightsSum += defaultWeight;
    }

    // Compute composite weighted risk score
    let compositeScore = 0;
    for (const [layer, weight] of Object.entries(weightsToApply)) {
      const normalizedWeight = weight / activeWeightsSum;
      compositeScore += (layerScores[layer] || 0) * normalizedWeight;
    }

    // Override: If Reputation actively lists target as MALICIOUS or Private IP SSRF triggered, enforce minimum HIGH/CRITICAL
    if (reputationLayer.isListedMalicious) {
      compositeScore = Math.max(compositeScore, 85);
    }
    if (hasPrivateIp) {
      compositeScore = Math.max(compositeScore, 95);
    }

    const finalRiskScore = Math.round(Math.min(100, Math.max(0, compositeScore)) * 10) / 10;

    // Determine Verdict and Risk Level
    let verdict: ThreatVerdict = 'SAFE';
    let riskLevel: RiskLevel = 'LOW';

    if (finalRiskScore > RISK_THRESHOLDS.HIGH_MAX) {
      verdict = 'PHISHING';
      riskLevel = 'CRITICAL';
    } else if (finalRiskScore > RISK_THRESHOLDS.SUSPICIOUS_MAX) {
      verdict = 'PHISHING';
      riskLevel = 'HIGH';
    } else if (finalRiskScore > RISK_THRESHOLDS.SAFE_MAX) {
      verdict = 'SUSPICIOUS';
      riskLevel = 'MEDIUM';
    } else {
      verdict = 'SAFE';
      riskLevel = 'LOW';
    }

    // Confidence Synthesis across active layers
    const confidence = Math.round(
      ((mlLayer.confidence * 0.4) +
        (urlLayer.status === 'SUCCESS' ? 0.15 : 0.05) +
        (domainLayer.status === 'SUCCESS' ? 0.15 : 0.05) +
        (dnsLayer.status === 'SUCCESS' ? 0.15 : 0.05) +
        (tlsLayer.status === 'SUCCESS' ? 0.15 : 0.05)) * 100
    ) / 100;

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

    return {
      riskScore: finalRiskScore,
      riskLevel,
      verdict,
      confidence: Math.min(1.0, Math.max(0.1, confidence)),
      evidence: sortedEvidence,
      layerScores
    };
  }
}

export const riskEngine = new RiskEngine();
