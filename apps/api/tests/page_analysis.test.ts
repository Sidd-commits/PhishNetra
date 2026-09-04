/**
 * PhishNetra - Page Content Analysis & Content Layer Unit Tests
 * Module: apps.api.tests.page_analysis.test
 * Milestone: 3
 */

import { contentLayer } from '../src/services/analysis/contentLayer';
import { PageAnalysisResult } from '@phishnetra/shared';

describe('Layer 7 & 8: Content and Brand Intelligence Layer', () => {
  it('should translate SSRF blocked page results into CRITICAL network evidence', () => {
    const blockedPage: PageAnalysisResult = {
      status: 'BLOCKED',
      requestedUrl: 'http://127.0.0.1:8080/admin',
      finalUrl: 'http://127.0.0.1:8080/admin',
      redirectCount: 0,
      redirectChain: [],
      forms: [],
      iframes: [],
      scripts: [],
      keywords: [],
      brandFindings: [],
      urgencyScore: 0,
      contentRiskScore: 90.0,
      phishingProbability: 0.90,
      confidence: 1.0,
      blockReason: 'Target IP 127.0.0.1 is a loopback address',
      acquisitionTimeMs: 1.5
    };

    const result = contentLayer.analyze(blockedPage);
    expect(result.data.status).toBe('FAILED');
    expect(result.evidence.some(e => e.layer === 'NETWORK' && e.severity === 'CRITICAL')).toBe(true);
    expect(result.evidence.some(e => e.featureKey === 'ssrf_security_block')).toBe(true);
  });

  it('should flag cross-origin credential forms with CRITICAL form evidence', () => {
    const phishingPage: PageAnalysisResult = {
      status: 'COMPLETED',
      requestedUrl: 'https://fake-login-service.xyz/login',
      finalUrl: 'https://fake-login-service.xyz/login',
      redirectCount: 1,
      redirectChain: [{ url: 'http://fake-login-service.xyz/login', status: 301 }],
      forms: [
        {
          id: 'login_form',
          name: 'loginForm',
          action: 'https://evil-harvest-collector.com/post.php',
          actionResolved: 'https://evil-harvest-collector.com/post.php',
          method: 'POST',
          target: '_self',
          isCrossOrigin: true,
          isIpAction: false,
          hasPasswordField: true,
          hasEmailField: true,
          hasCreditCardField: false,
          hasOtpField: false,
          passwordFieldCount: 1,
          inputCount: 2,
          description: 'Login form submits data to external domain (evil-harvest-collector.com)'
        }
      ],
      iframes: [],
      scripts: [],
      keywords: [{ category: 'authentication', count: 2, matchedTerms: ['login', 'password'] }],
      brandFindings: [],
      urgencyScore: 0,
      contentRiskScore: 65.0,
      phishingProbability: 0.65,
      confidence: 0.90,
      acquisitionTimeMs: 220
    };

    const result = contentLayer.analyze(phishingPage);
    expect(result.data.status).toBe('SUCCESS');
    expect(result.evidence.some(e => e.layer === 'FORM' && e.featureKey === 'cross_origin_credential_form')).toBe(true);
    expect(result.evidence.find(e => e.featureKey === 'cross_origin_credential_form')?.severity).toBe('CRITICAL');
  });

  it('should detect Brand Domain Mismatches and produce CRITICAL brand evidence', () => {
    const brandMismatchPage: PageAnalysisResult = {
      status: 'COMPLETED',
      requestedUrl: 'http://unrelated-domain.com/ms-login',
      finalUrl: 'http://unrelated-domain.com/ms-login',
      redirectCount: 0,
      redirectChain: [],
      forms: [
        {
          action: '/auth',
          actionResolved: 'http://unrelated-domain.com/auth',
          method: 'POST',
          isCrossOrigin: false,
          isIpAction: false,
          hasPasswordField: true,
          hasEmailField: true,
          hasCreditCardField: false,
          hasOtpField: false,
          passwordFieldCount: 1,
          inputCount: 2
        }
      ],
      iframes: [],
      scripts: [],
      keywords: [{ category: 'authentication', count: 3, matchedTerms: ['login', 'password', 'sign in'] }],
      brandFindings: [
        {
          claimedBrand: 'Microsoft',
          authenticDomain: 'microsoft.com',
          actualDomain: 'unrelated-domain.com',
          isMismatch: true,
          confidence: 0.95,
          matchSources: ["Title contains 'Microsoft'"],
          description: "Page strongly references 'Microsoft' but is hosted on unrelated domain 'unrelated-domain.com'"
        }
      ],
      urgencyScore: 0.2,
      contentRiskScore: 70.0,
      phishingProbability: 0.70,
      confidence: 0.95,
      acquisitionTimeMs: 180
    };

    const result = contentLayer.analyze(brandMismatchPage);
    expect(result.data.brandMismatch).toBe(true);
    expect(result.data.claimedBrand).toBe('Microsoft');
    expect(result.evidence.some(e => e.layer === 'BRAND' && e.featureKey === 'brand_domain_mismatch' && e.severity === 'CRITICAL')).toBe(true);
  });
});
