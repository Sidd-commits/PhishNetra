import {
  FAIRRiskParams,
  FAIRRiskAssessmentResult
} from '@phishnetra/shared';
import crypto from 'crypto';
import { auditLogService } from '../audit/AuditLogService';

export class CyberRiskQuantificationService {
  public calculateFAIRRisk(params: FAIRRiskParams): FAIRRiskAssessmentResult {
    const assessmentId = `fair-${crypto.randomUUID()}`;
    const calculatedAt = new Date().toISOString();

    // 1. Vulnerability Ratio: V = susceptibilityRate * (1 - controlEffectiveness)
    const vulnerabilityRatio = Number(
      (params.susceptibilityRate * (1 - params.controlEffectiveness)).toFixed(4)
    );

    // 2. Loss Event Frequency (LEF): events per year that result in unauthorized access
    const lossEventFrequency = Number(
      (params.annualPhishingAttempts * vulnerabilityRatio).toFixed(2)
    );

    // 3. Primary Loss Expected: direct response, password reset, SOC investigation
    const primaryLossExpected = Math.round(
      lossEventFrequency * params.costPerCompromisedCredential
    );

    // 4. Secondary Loss Expected: regulatory notification, penalties, PR impact
    const secondaryProbability = Math.min(
      1.0,
      lossEventFrequency * params.secondaryRegulatoryFineLikelihood * 0.1
    );
    const secondaryLossExpected = Math.round(
      secondaryProbability * (params.maxRegulatoryFine * 0.2)
    );

    // 5. Total Expected Annual Loss (ALE)
    const totalExpectedAnnualLoss = primaryLossExpected + secondaryLossExpected;

    // 6. Loss without PhishNetra controls (baseline comparison)
    const unmitigatedLEF = params.annualPhishingAttempts * params.susceptibilityRate;
    const unmitigatedPrimaryLoss = unmitigatedLEF * params.costPerCompromisedCredential;
    const unmitigatedSecondaryLoss = Math.min(1.0, unmitigatedLEF * params.secondaryRegulatoryFineLikelihood * 0.2) * (params.maxRegulatoryFine * 0.35);
    const unmitigatedTotal = Math.round(unmitigatedPrimaryLoss + unmitigatedSecondaryLoss);

    // 7. Value Mitigated & Defense ROI
    const annualLossMitigatedByPhishNetra = Math.max(0, unmitigatedTotal - totalExpectedAnnualLoss);
    const estimatedPlatformAnnualCost = 24000; // Enterprise deployment cost baseline
    const defenseRoiMultiple = Number(
      (annualLossMitigatedByPhishNetra / estimatedPlatformAnnualCost).toFixed(1)
    );

    // 8. Probabilistic Loss Distribution (10th, 50th, 90th percentiles)
    const lossDistribution = {
      tenthPercentile: Math.round(totalExpectedAnnualLoss * 0.42),
      fiftiethPercentile: totalExpectedAnnualLoss,
      ninetiethPercentile: Math.round(totalExpectedAnnualLoss * 2.35),
      expectedAnnualLoss: totalExpectedAnnualLoss
    };

    // 9. Risk Tier assignment
    let riskTier: FAIRRiskAssessmentResult['riskTier'] = 'LOW';
    if (totalExpectedAnnualLoss >= 1000000) {
      riskTier = 'CRITICAL';
    } else if (totalExpectedAnnualLoss >= 500000) {
      riskTier = 'HIGH';
    } else if (totalExpectedAnnualLoss >= 200000) {
      riskTier = 'ELEVATED';
    } else if (totalExpectedAnnualLoss >= 50000) {
      riskTier = 'MODERATE';
    }

    auditLogService.log({
      actor: 'SYSTEM',
      action: 'FAIR_CYBER_RISK_CALCULATED',
      details: JSON.stringify({
        assessmentId,
        totalExpectedAnnualLoss,
        lossEventFrequency,
        riskTier,
        defenseRoiMultiple
      }),
      category: 'CONFIG',
      severity: 'INFO'
    });

    return {
      assessmentId,
      calculatedAt,
      lossEventFrequency,
      vulnerabilityRatio,
      primaryLossExpected,
      secondaryLossExpected,
      totalExpectedAnnualLoss,
      annualLossMitigatedByPhishNetra,
      defenseRoiMultiple,
      lossDistribution,
      riskTier
    };
  }
}

export const cyberRiskQuantificationService = new CyberRiskQuantificationService();
