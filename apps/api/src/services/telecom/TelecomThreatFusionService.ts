import crypto from 'crypto';
import {
  TelecomThreatProbe,
  TelecomThreatAssessment
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class TelecomThreatFusionService {
  private static instance: TelecomThreatFusionService;
  private readonly assessmentHistory: TelecomThreatAssessment[] = [];

  private constructor() {}

  public static getInstance(): TelecomThreatFusionService {
    if (!TelecomThreatFusionService.instance) {
      TelecomThreatFusionService.instance = new TelecomThreatFusionService();
    }
    return TelecomThreatFusionService.instance;
  }

  public assessThreat(probe: TelecomThreatProbe): TelecomThreatAssessment {
    const assessmentId = `telecom-${crypto.randomBytes(6).toString('hex')}`;
    const evaluatedAt = new Date().toISOString();
    const anomaliesDetected: string[] = [];

    // 1. STIR/SHAKEN Attestation Evaluation
    let attestationRisk = 0;
    switch (probe.stirShakenAttestation) {
      case 'UNATTESTED':
        attestationRisk = 50;
        anomaliesDetected.push('STIR/SHAKEN: Unattested telecom origination');
        break;
      case 'C':
        attestationRisk = 35;
        anomaliesDetected.push('STIR/SHAKEN: Level C (Gateway transit attestation only)');
        break;
      case 'B':
        attestationRisk = 15;
        anomaliesDetected.push('STIR/SHAKEN: Level B (Customer authenticated, caller ID unverified)');
        break;
      case 'A':
        attestationRisk = 0;
        break;
    }

    // 2. Caller ID / Sender ID Heuristics
    const sender = probe.callerOrSenderId.toUpperCase();
    const spoofedSenderIndicators = ['ALERT', 'SECURITY', 'VERIFY', 'SUPPORT', 'BANK', 'AUTH', 'CHASE', 'APPLE', 'AMAZON'];
    const hasSpoofedBrandTag = spoofedSenderIndicators.some(brand => sender.includes(brand));
    if (hasSpoofedBrandTag && !probe.callerOrSenderId.startsWith('+')) {
      anomaliesDetected.push(`Alphanumeric Sender ID brand spoofing pattern: ${probe.callerOrSenderId}`);
    }

    // 3. Social Engineering & Urgency Analysis
    const textLower = probe.messageOrTranscript.toLowerCase();
    const urgencyKeywords = [
      'suspended', 'compromised', 'immediately', 'verify', 'one-time code',
      'otp', 'wire transfer', 'press 1', 'fraud specialist', 'gift card',
      'unauthorized transaction', 'arrest warrant'
    ];

    let urgencyHits = 0;
    for (const kw of urgencyKeywords) {
      if (textLower.includes(kw)) urgencyHits++;
    }
    const urgencySocialEngineeringScore = Math.min(100, Math.round(urgencyHits * 18 + (hasSpoofedBrandTag ? 25 : 0)));

    // 4. Synthetic Voice Likelihood (for VoIP vishing)
    let syntheticVoiceLikelihood = 15;
    if (probe.channel === 'VOIP_VISHING' || probe.channel === 'CROSS_CHANNEL') {
      const syntheticPhrasingMarkers = [
        'this is an automated message',
        'do not hang up',
        'your social security number has been',
        'department of homeland security'
      ];
      let synthHits = 0;
      for (const sm of syntheticPhrasingMarkers) {
        if (textLower.includes(sm)) synthHits++;
      }
      syntheticVoiceLikelihood = Math.min(95, Math.round(synthHits * 30 + (probe.stirShakenAttestation === 'UNATTESTED' ? 25 : 10)));
      if (syntheticVoiceLikelihood >= 60) {
        anomaliesDetected.push(`Acoustic/Script anomaly: High synthetic voice likelihood (${syntheticVoiceLikelihood}%)`);
      }
    }

    // 5. URL Multi-Vector Infiltration
    const urlRiskBoost = probe.extractedUrls.length > 0 ? 30 : 0;
    if (probe.extractedUrls.length > 0) {
      anomaliesDetected.push(`Smishing payload contains ${probe.extractedUrls.length} extracted web link(s)`);
    }

    // 6. Multi-Vector Convergence Index (MVCI)
    const convergenceSum = attestationRisk * 0.35 +
      urgencySocialEngineeringScore * 0.30 +
      syntheticVoiceLikelihood * 0.20 +
      urlRiskBoost;
    const multiVectorConvergenceIndex = Math.min(100, Math.round(convergenceSum));

    // 7. Verdict and Action
    let verdict: TelecomThreatAssessment['verdict'] = 'LEGITIMATE';
    let recommendedTelecomAction: TelecomThreatAssessment['recommendedTelecomAction'] = 'ALLOW';

    if (multiVectorConvergenceIndex >= 70) {
      verdict = 'CRITICAL_CONVERGENCE';
      recommendedTelecomAction = 'CARRIER_BLOCK_DISPATCH';
    } else if (multiVectorConvergenceIndex >= 40) {
      verdict = 'SUSPICIOUS';
      recommendedTelecomAction = 'FLAG_SUSPICIOUS';
    } else {
      verdict = 'LEGITIMATE';
      recommendedTelecomAction = 'ALLOW';
    }

    const assessment: TelecomThreatAssessment = {
      assessmentId,
      evaluatedAt,
      channel: probe.channel,
      callerOrSenderId: probe.callerOrSenderId,
      stirShakenAttestation: probe.stirShakenAttestation,
      syntheticVoiceLikelihood,
      urgencySocialEngineeringScore,
      multiVectorConvergenceIndex,
      correlatedCampaignId: multiVectorConvergenceIndex >= 60 ? `CAMP-TEL-${crypto.randomBytes(3).toString('hex').toUpperCase()}` : undefined,
      anomaliesDetected,
      verdict,
      recommendedTelecomAction
    };

    this.assessmentHistory.unshift(assessment);
    if (this.assessmentHistory.length > 100) {
      this.assessmentHistory.pop();
    }

    if (verdict === 'CRITICAL_CONVERGENCE') {
      auditLogService.log({
        actor: 'TelecomThreatFusionService',
        action: 'TELECOM_MULTI_VECTOR_CONVERGENCE_DETECTED',
        category: 'SECURITY',
        severity: 'CRITICAL',
        details: JSON.stringify({
          assessmentId,
          channel: probe.channel,
          sender: probe.callerOrSenderId,
          mvci: multiVectorConvergenceIndex,
          action: recommendedTelecomAction
        })
      });
    }

    return assessment;
  }

  public getHistory(): TelecomThreatAssessment[] {
    return [...this.assessmentHistory];
  }
}

export const telecomThreatFusionService = TelecomThreatFusionService.getInstance();
