import { urlLayer } from '../src/services/analysis/urlLayer';
import { domainLayer } from '../src/services/analysis/domainLayer';
import { DNSLayer } from '../src/services/analysis/dnsLayer';
import { tlsLayer } from '../src/services/analysis/tlsLayer';
import { ReputationLayer, IReputationProvider } from '../src/services/analysis/reputationLayer';
import { canonicalizeUrl } from '../src/services/analysis/canonicalization';

describe('Layer 1: URL Intelligence Layer', () => {
  it('should detect URL shorteners and add evidence', () => {
    const canonical = canonicalizeUrl('https://bit.ly/secure-login-3948');
    const { data, evidence } = urlLayer.analyze(canonical);
    expect(data.isShortener).toBe(true);
    expect(data.shortenerProvider).toBe('bit.ly');
    expect(evidence.some(e => e.featureKey === 'url_shortener_detected')).toBe(true);
  });

  it('should detect userinfo credentials trick (@ in authority)', () => {
    const canonical = canonicalizeUrl('http://admin:secret@malicious-host.com/path');
    const { data, evidence } = urlLayer.analyze(canonical);
    expect(data.hasUserInfo).toBe(true);
    expect(evidence.some(e => e.featureKey === 'userinfo_in_url')).toBe(true);
  });

  it('should extract obfuscated percent-encoded structural delimiters', () => {
    const canonical = canonicalizeUrl('http://example.com/%2Fpath%40fake');
    const { data, evidence } = urlLayer.analyze(canonical);
    expect(data.obfuscatedEncodings).toContain('%2F');
    expect(data.obfuscatedEncodings).toContain('%40');
    expect(evidence.some(e => e.featureKey === 'obfuscated_hex_sequences')).toBe(true);
  });
});

describe('Layer 2: Domain Intelligence & RDAP', () => {
  it('should skip RDAP queries for raw IP targets safely', async () => {
    const { data, evidence } = await domainLayer.analyze('192.168.1.100');
    expect(data.status).toBe('SKIPPED');
    expect(data.domainAgeDays).toBeNull();
    expect(evidence.length).toBe(0);
  });

  it('should correctly parse registrable domain and subdomains', async () => {
    const { data } = await domainLayer.analyze('auth.stage.paypal.com');
    expect(data.registrableDomain).toBe('paypal.com');
    expect(data.subdomain).toBe('auth.stage');
    expect(data.tld).toBe('com');
  });
});

describe('Layer 3: DNS & IP Intelligence', () => {
  it('should flag private RFC1918 IPs as CRITICAL SSRF risks', async () => {
    const customDns = new DNSLayer();
    const { data, evidence } = await customDns.analyze('192.168.1.50');
    expect(data.status).toBe('SUCCESS');
    expect(data.resolvedIps).toContain('192.168.1.50');
    const ssrfEvidence = evidence.find(e => e.featureKey === 'private_ip_resolution');
    expect(ssrfEvidence).toBeDefined();
    expect(ssrfEvidence?.severity).toBe('CRITICAL');
  });
});

describe('Layer 4: TLS Intelligence', () => {
  it('should flag plain HTTP targets with unencrypted warning evidence', async () => {
    const { data, evidence } = await tlsLayer.analyze('http:', 'example.com', 80);
    expect(data.hasTls).toBe(false);
    expect(data.certificateValid).toBe(false);
    expect(evidence.some(e => e.featureKey === 'unencrypted_http_protocol')).toBe(true);
  });
});

describe('Layer 5: Reputation Intelligence Provider Abstraction', () => {
  it('should handle unconfigured providers without throwing errors', async () => {
    const mockProvider: IReputationProvider = {
      name: 'MockUnconfigured',
      isConfigured: () => false,
      checkUrl: async () => ({
        providerName: 'MockUnconfigured',
        status: 'NOT_CONFIGURED',
        isConfigured: false,
        malicious: false,
        suspicious: false,
        harmless: false,
        confidence: 0,
        threatType: null
      })
    };

    const repLayer = new ReputationLayer([mockProvider]);
    const { data, evidence } = await repLayer.analyze('https://example.com', 'example.com');
    expect(data.status).toBe('PARTIAL');
    expect(data.isListedMalicious).toBe(false);
    expect(data.providers[0].status).toBe('NOT_CONFIGURED');
  });

  it('should trigger CRITICAL evidence when a provider reports active blacklist hit', async () => {
    const mockMaliciousProvider: IReputationProvider = {
      name: 'MalwareFeed',
      isConfigured: () => true,
      checkUrl: async () => ({
        providerName: 'MalwareFeed',
        status: 'SUCCESS',
        isConfigured: true,
        malicious: true,
        suspicious: false,
        harmless: false,
        confidence: 0.99,
        threatType: 'credential_harvesting',
        details: 'Active phishing campaign targeting online banking'
      })
    };

    const repLayer = new ReputationLayer([mockMaliciousProvider]);
    const { data, evidence } = await repLayer.analyze('https://evil-login.com', 'evil-login.com');
    expect(data.isListedMalicious).toBe(true);
    expect(data.reputationScore).toBe(100);
    const hitEvidence = evidence.find(e => e.featureKey === 'reputation_blacklist_hit');
    expect(hitEvidence).toBeDefined();
    expect(hitEvidence?.severity).toBe('CRITICAL');
  });
});
