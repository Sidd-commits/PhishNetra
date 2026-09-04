/**
 * PhishNetra - Content Intelligence Layer (Layer 7 & 8: Content & Brand Signals)
 * Module: apps.api.src.services.analysis.contentLayer
 * Milestone: 3
 */

import {
  EvidenceItem,
  LayerStatus,
  PageAnalysisResult
} from '@phishnetra/shared';

export interface ContentLayerAnalysisResult {
  data: {
    status: LayerStatus;
    contentRiskScore: number;
    urgencyScore: number;
    redirectCount: number;
    formsCount: number;
    passwordInputsCount: number;
    brandMismatch: boolean;
    claimedBrand: string | null;
  };
  evidence: EvidenceItem[];
}

export class ContentLayer {
  public analyze(pageResult: PageAnalysisResult): ContentLayerAnalysisResult {
    const evidence: EvidenceItem[] = [];

    // Map PageAnalysisStatus to LayerStatus
    let layerStatus: LayerStatus = 'SUCCESS';
    if (pageResult.status === 'BLOCKED') {
      layerStatus = 'FAILED';
    } else if (pageResult.status === 'FAILED' || pageResult.status === 'TIMEOUT') {
      layerStatus = 'FAILED';
    } else if (pageResult.status === 'NOT_REQUESTED' || pageResult.status === 'SKIPPED') {
      layerStatus = 'SKIPPED';
    }

    // 1. SSRF & Security Block Evidence
    if (pageResult.status === 'BLOCKED') {
      evidence.push({
        layer: 'NETWORK',
        featureKey: 'ssrf_security_block',
        featureValue: pageResult.blockReason || 'Prohibited destination IP',
        severity: 'CRITICAL',
        description: `Zero-Trust SSRF Shield blocked webpage acquisition: ${pageResult.blockReason || 'Target resolved to prohibited IP range'}`,
        contribution: 0.40,
        source: 'SSRF_Defense_Shield',
        confidence: 1.0
      });
    }

    // 2. Redirect Chain Evidence
    if (pageResult.redirectCount >= 2) {
      evidence.push({
        layer: 'NETWORK',
        featureKey: 'redirect_chain',
        featureValue: `${pageResult.redirectCount} hops`,
        severity: pageResult.redirectCount >= 4 ? 'HIGH' : 'MEDIUM',
        description: `Page navigated through ${pageResult.redirectCount} redirect hops before reaching final destination (${pageResult.finalUrl}).`,
        contribution: 0.15,
        source: 'Browser_Isolation',
        confidence: 0.90
      });
    }

    // 3. Form & Credential Theft Evidence
    let hasBrandMismatch = false;
    let claimedBrandName: string | null = null;

    for (const form of pageResult.forms || []) {
      if (form.hasPasswordField && (form.isCrossOrigin || form.isIpAction)) {
        evidence.push({
          layer: 'FORM',
          featureKey: 'cross_origin_credential_form',
          featureValue: form.actionResolved,
          severity: 'CRITICAL',
          description: `High Risk: Form requests password credentials and submits data to external destination (${form.actionResolved}).`,
          contribution: 0.35,
          source: 'Form_Analyzer',
          confidence: 0.95
        });
      } else if (form.hasPasswordField) {
        evidence.push({
          layer: 'FORM',
          featureKey: 'credential_form',
          featureValue: `${form.passwordFieldCount} password field(s)`,
          severity: 'MEDIUM',
          description: `Page contains authentication form requesting user credentials (${form.description || 'Password input'}).`,
          contribution: 0.15,
          source: 'Form_Analyzer',
          confidence: 0.90
        });
      }

      if (form.hasCreditCardField) {
        evidence.push({
          layer: 'FORM',
          featureKey: 'financial_card_input',
          featureValue: 'Credit Card / CVV Field',
          severity: 'HIGH',
          description: 'Page presents input fields requesting sensitive payment card / CVV details.',
          contribution: 0.25,
          source: 'Form_Analyzer',
          confidence: 0.95
        });
      }
    }

    // 4. Brand Impersonation & Consistency Evidence
    for (const brand of pageResult.brandFindings || []) {
      claimedBrandName = brand.claimedBrand;
      if (brand.isMismatch) {
        hasBrandMismatch = true;
        evidence.push({
          layer: 'BRAND',
          featureKey: 'brand_domain_mismatch',
          featureValue: `${brand.claimedBrand} vs ${brand.actualDomain}`,
          severity: 'CRITICAL',
          description: `Brand Impersonation: Page strongly references '${brand.claimedBrand}' but is hosted on unrelated domain '${brand.actualDomain}' (Authentic: ${brand.authenticDomain}).`,
          contribution: 0.40,
          source: 'Brand_Consistency_Engine',
          confidence: brand.confidence
        });
      } else {
        evidence.push({
          layer: 'BRAND',
          featureKey: 'verified_brand_domain',
          featureValue: `${brand.claimedBrand} on ${brand.actualDomain}`,
          severity: 'INFO',
          description: `Page references '${brand.claimedBrand}' on its authentic verified domain (${brand.actualDomain}).`,
          contribution: 0.0,
          source: 'Brand_Consistency_Engine',
          confidence: brand.confidence
        });
      }
    }

    // 5. JavaScript Obfuscation & Evasion Evidence
    for (const script of pageResult.scripts || []) {
      if (script.hasObfuscation || script.hasEval) {
        evidence.push({
          layer: 'CONTENT',
          featureKey: 'obfuscated_javascript',
          featureValue: script.reasons.join('; ') || 'Hex/Packed encoding',
          severity: 'HIGH',
          description: `Suspicious client-side script behavior: ${script.reasons.join(', ')}.`,
          contribution: 0.20,
          source: 'JS_Heuristics',
          confidence: 0.85
        });
        break;
      }
    }

    // 6. Social Engineering & Urgency Evidence
    if (pageResult.urgencyScore > 0.3) {
      evidence.push({
        layer: 'CONTENT',
        featureKey: 'urgency_social_engineering',
        featureValue: `Score ${Math.round(pageResult.urgencyScore * 100)}%`,
        severity: pageResult.urgencyScore > 0.6 ? 'HIGH' : 'MEDIUM',
        description: 'Page text contains psychological urgency patterns designed to induce panic (e.g. account suspended, immediate action required).',
        contribution: 0.15,
        source: 'Linguistic_Analyzer',
        confidence: 0.80
      });
    }

    // 7. Hidden Iframe Evidence
    const hiddenIframes = (pageResult.iframes || []).filter(ifr => ifr.isHidden);
    if (hiddenIframes.length > 0) {
      evidence.push({
        layer: 'CONTENT',
        featureKey: 'hidden_iframe_detected',
        featureValue: `${hiddenIframes.length} hidden iframe(s)`,
        severity: 'HIGH',
        description: `Page embeds ${hiddenIframes.length} hidden or zero-dimension iframe(s) capable of silent payload loading.`,
        contribution: 0.20,
        source: 'DOM_Analyzer',
        confidence: 0.90
      });
    }

    return {
      data: {
        status: layerStatus,
        contentRiskScore: pageResult.contentRiskScore || 0,
        urgencyScore: pageResult.urgencyScore || 0,
        redirectCount: pageResult.redirectCount || 0,
        formsCount: pageResult.forms?.length || 0,
        passwordInputsCount: pageResult.domMetrics?.passwordInputsCount || 0,
        brandMismatch: hasBrandMismatch,
        claimedBrand: claimedBrandName
      },
      evidence
    };
  }
}

export const contentLayer = new ContentLayer();
