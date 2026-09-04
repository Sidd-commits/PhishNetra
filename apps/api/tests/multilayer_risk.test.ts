import { riskEngine } from '../src/services/RiskEngine';
import {
  URLIntelligence,
  DomainIntelligence,
  DNSIntelligence,
  TLSIntelligence,
  ReputationIntelligence,
  MLIntelligence,
  PageAnalysisResult
} from '@phishnetra/shared';

describe('Multi-Layer Risk Engine Unit Tests', () => {
  const dummyUrlFeatures = {
    url_length: 25,
    hostname_length: 15,
    path_length: 10,
    query_length: 0,
    subdomain_count: 0,
    has_ip_address: 0,
    has_https: 1,
    special_char_count: 2,
    digit_count: 0,
    hyphen_count: 0,
    at_symbol_count: 0,
    double_slash_in_path: 0,
    encoded_char_count: 0,
    suspicious_keyword_count: 0,
    entropy: 3.2,
    tld_in_subdomain: 0,
    port_in_url: 0,
    tld_length: 3
  };

  it('should classify completely legitimate multi-layer signals as SAFE with LOW risk', () => {
    const urlLayer: URLIntelligence = {
      status: 'SUCCESS',
      canonicalUrl: 'https://example.com/docs',
      hostname: 'example.com',
      path: '/docs',
      query: '',
      isShortener: false,
      shortenerProvider: null,
      isPunycode: false,
      unicodeHostname: null,
      hasUserInfo: false,
      hasCustomPort: false,
      customPort: null,
      obfuscatedEncodings: [],
      digitRatio: 0,
      specialCharRatio: 0.05,
      hyphenRatio: 0,
      entropy: 3.2,
      features: dummyUrlFeatures
    };

    const domainLayer: DomainIntelligence = {
      status: 'SUCCESS',
      domain: 'example.com',
      registrableDomain: 'example.com',
      tld: 'com',
      subdomain: '',
      registrar: 'MarkMonitor',
      creationDate: '1995-08-14T04:00:00Z',
      expirationDate: '2028-08-13T04:00:00Z',
      domainAgeDays: 10000,
      domainAgeCategory: '> 365 days',
      isPrivacyProtected: false
    };

    const dnsLayer: DNSIntelligence = {
      status: 'SUCCESS',
      resolvedIps: ['93.184.216.34'],
      ipv4Count: 1,
      ipv6Count: 0,
      nameservers: ['a.iana-servers.net'],
      mxRecords: [],
      cnameRecords: [],
      txtRecords: [],
      hasMx: false,
      ipDetails: [{ ip: '93.184.216.34', version: 'IPv4', asn: 'AS15133', org: 'EDGECAST', country: 'US' }]
    };

    const tlsLayer: TLSIntelligence = {
      status: 'SUCCESS',
      hasTls: true,
      certificateValid: true,
      certificateExpired: false,
      hostnameMatches: true,
      validFrom: '2025-01-01T00:00:00Z',
      validTo: '2026-01-01T00:00:00Z',
      daysUntilExpiry: 120,
      issuer: 'DigiCert Inc',
      subject: 'example.com',
      sans: ['example.com'],
      tlsVersion: 'TLSv1.3',
      zeroTrustWarning: 'Transport valid'
    };

    const reputationLayer: ReputationIntelligence = {
      status: 'SUCCESS',
      providers: [{
        providerName: 'URLhaus',
        status: 'SUCCESS',
        isConfigured: true,
        malicious: false,
        suspicious: false,
        harmless: true,
        confidence: 0.90
      }],
      isListedMalicious: false,
      reputationScore: 0
    };

    const mlLayer: MLIntelligence = {
      status: 'SUCCESS',
      phishingProbability: 0.02,
      confidence: 0.96,
      predictedLabel: 0,
      modelVersion: 'v0.1.0-baseline',
      inferenceTimeMs: 1.0
    };

    const pageLayer: PageAnalysisResult = {
      status: 'COMPLETED',
      requestedUrl: 'https://example.com/docs',
      finalUrl: 'https://example.com/docs',
      redirectCount: 0,
      redirectChain: [],
      forms: [],
      iframes: [],
      scripts: [],
      keywords: [],
      brandFindings: [],
      urgencyScore: 0,
      contentRiskScore: 5.0,
      phishingProbability: 0.05,
      confidence: 0.95,
      acquisitionTimeMs: 100
    };

    const result = riskEngine.evaluateMultiLayer({
      urlLayer,
      domainLayer,
      dnsLayer,
      tlsLayer,
      reputationLayer,
      mlLayer,
      pageLayer,
      layerEvidences: []
    });

    expect(result.verdict).toBe('SAFE');
    expect(result.riskLevel).toBe('LOW');
    expect(result.riskScore).toBeLessThan(25);
    expect(result.summary).toContain('PhishNetra Analysis Summary');
  });

  it('should trigger CRITICAL / PHISHING when Brand Domain Mismatch is detected', () => {
    const urlLayer: URLIntelligence = {
      status: 'SUCCESS',
      canonicalUrl: 'https://verify-microsoft-security.xyz/login',
      hostname: 'verify-microsoft-security.xyz',
      path: '/login',
      query: '',
      isShortener: false,
      shortenerProvider: null,
      isPunycode: false,
      unicodeHostname: null,
      hasUserInfo: false,
      hasCustomPort: false,
      customPort: null,
      obfuscatedEncodings: [],
      digitRatio: 0,
      specialCharRatio: 0.05,
      hyphenRatio: 0.1,
      entropy: 3.8,
      features: { ...dummyUrlFeatures, suspicious_keyword_count: 2 }
    };

    const domainLayer: DomainIntelligence = {
      status: 'SUCCESS',
      domain: 'verify-microsoft-security.xyz',
      registrableDomain: 'verify-microsoft-security.xyz',
      tld: 'xyz',
      subdomain: '',
      domainAgeDays: 5,
      domainAgeCategory: '< 30 days',
      isPrivacyProtected: true
    };

    const dnsLayer: DNSIntelligence = {
      status: 'SUCCESS',
      resolvedIps: ['198.51.100.22'],
      ipv4Count: 1,
      ipv6Count: 0,
      nameservers: [],
      mxRecords: [],
      cnameRecords: [],
      txtRecords: [],
      hasMx: false,
      ipDetails: []
    };

    const tlsLayer: TLSIntelligence = {
      status: 'SUCCESS',
      hasTls: true,
      certificateValid: true,
      certificateExpired: false,
      hostnameMatches: true,
      daysUntilExpiry: 80,
      sans: ['verify-microsoft-security.xyz'],
      zeroTrustWarning: 'Transport valid'
    };

    const reputationLayer: ReputationIntelligence = {
      status: 'SUCCESS',
      providers: [],
      isListedMalicious: false,
      reputationScore: 0
    };

    const mlLayer: MLIntelligence = {
      status: 'SUCCESS',
      phishingProbability: 0.65,
      confidence: 0.80,
      predictedLabel: 1,
      modelVersion: 'v0.1.0-baseline',
      inferenceTimeMs: 1.0
    };

    const pageLayer: PageAnalysisResult = {
      status: 'COMPLETED',
      requestedUrl: 'https://verify-microsoft-security.xyz/login',
      finalUrl: 'https://verify-microsoft-security.xyz/login',
      redirectCount: 0,
      redirectChain: [],
      forms: [
        {
          action: '/post',
          actionResolved: 'https://verify-microsoft-security.xyz/post',
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
      keywords: [{ category: 'authentication', count: 3, matchedTerms: ['login', 'password'] }],
      brandFindings: [
        {
          claimedBrand: 'Microsoft',
          authenticDomain: 'microsoft.com',
          actualDomain: 'verify-microsoft-security.xyz',
          isMismatch: true,
          confidence: 0.95,
          matchSources: ["Title contains 'Microsoft'"]
        }
      ],
      urgencyScore: 0.3,
      contentRiskScore: 75.0,
      phishingProbability: 0.75,
      confidence: 0.95,
      acquisitionTimeMs: 150
    };

    const result = riskEngine.evaluateMultiLayer({
      urlLayer,
      domainLayer,
      dnsLayer,
      tlsLayer,
      reputationLayer,
      mlLayer,
      pageLayer,
      layerEvidences: []
    });

    expect(result.verdict).toBe('PHISHING');
    expect(result.riskLevel).toBe('CRITICAL');
    expect(result.riskScore).toBeGreaterThanOrEqual(80);
    expect(result.summary).toContain('Microsoft');
  });
});
