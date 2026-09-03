import { riskEngine } from '../src/services/RiskEngine';
import {
  URLIntelligence,
  DomainIntelligence,
  DNSIntelligence,
  TLSIntelligence,
  ReputationIntelligence,
  MLIntelligence
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

    const result = riskEngine.evaluateMultiLayer({
      urlLayer,
      domainLayer,
      dnsLayer,
      tlsLayer,
      reputationLayer,
      mlLayer,
      layerEvidences: []
    });

    expect(result.verdict).toBe('SAFE');
    expect(result.riskLevel).toBe('LOW');
    expect(result.riskScore).toBeLessThan(25);
  });

  it('should trigger CRITICAL / PHISHING when multiple high-severity signals align', () => {
    const urlLayer: URLIntelligence = {
      status: 'SUCCESS',
      canonicalUrl: 'http://192.168.1.50:8080/paypal-update/login.php',
      hostname: '192.168.1.50',
      path: '/paypal-update/login.php',
      query: '',
      isShortener: false,
      shortenerProvider: null,
      isPunycode: false,
      unicodeHostname: null,
      hasUserInfo: false,
      hasCustomPort: true,
      customPort: 8080,
      obfuscatedEncodings: [],
      digitRatio: 0.25,
      specialCharRatio: 0.15,
      hyphenRatio: 0.10,
      entropy: 4.8,
      features: {
        ...dummyUrlFeatures,
        has_ip_address: 1,
        has_https: 0,
        port_in_url: 1,
        suspicious_keyword_count: 3
      }
    };

    const domainLayer: DomainIntelligence = {
      status: 'SKIPPED',
      domain: '192.168.1.50',
      registrableDomain: '192.168.1.50',
      tld: '',
      subdomain: '',
      domainAgeDays: null,
      domainAgeCategory: 'unknown',
      isPrivacyProtected: false
    };

    const dnsLayer: DNSIntelligence = {
      status: 'SUCCESS',
      resolvedIps: ['192.168.1.50'],
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
      hasTls: false,
      certificateValid: false,
      certificateExpired: false,
      hostnameMatches: false,
      daysUntilExpiry: null,
      sans: [],
      zeroTrustWarning: 'Plain HTTP'
    };

    const reputationLayer: ReputationIntelligence = {
      status: 'SUCCESS',
      providers: [],
      isListedMalicious: false,
      reputationScore: 0
    };

    const mlLayer: MLIntelligence = {
      status: 'SUCCESS',
      phishingProbability: 0.88,
      confidence: 0.76,
      predictedLabel: 1,
      modelVersion: 'v0.1.0-baseline',
      inferenceTimeMs: 1.2
    };

    const result = riskEngine.evaluateMultiLayer({
      urlLayer,
      domainLayer,
      dnsLayer,
      tlsLayer,
      reputationLayer,
      mlLayer,
      layerEvidences: []
    });

    expect(result.verdict).toBe('PHISHING');
    expect(result.riskLevel).toBe('CRITICAL');
    expect(result.riskScore).toBeGreaterThanOrEqual(80);
  });
});
