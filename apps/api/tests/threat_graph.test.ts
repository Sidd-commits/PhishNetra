import { ThreatGraphEngine } from '../src/services/graph/ThreatGraphEngine';
import { STIXExportService } from '../src/services/graph/STIXExportService';
import { AnalysisResponse } from '@phishnetra/shared';

describe('Threat Graph Engine Suite', () => {
  it('should upsert nodes and edges accurately', async () => {
    const node1 = await ThreatGraphEngine.upsertNode(
      'domain:attacker-phish.xyz',
      'attacker-phish.xyz',
      'DOMAIN',
      { isPhishing: true },
      88,
      'CRITICAL'
    );
    expect(node1).toBeDefined();
    expect(node1.id).toBe('domain:attacker-phish.xyz');

    const node2 = await ThreatGraphEngine.upsertNode(
      'ip:185.220.101.5',
      '185.220.101.5',
      'IP',
      { country: 'NL', asn: 'AS200052' },
      70,
      'HIGH'
    );
    expect(node2).toBeDefined();

    const edge = await ThreatGraphEngine.upsertEdge(
      node1.id,
      node2.id,
      'RESOLVES_TO',
      1.0
    );
    expect(edge).toBeDefined();
    expect(edge.sourceId).toBe(node1.id);
    expect(edge.targetId).toBe(node2.id);
  });

  it('should ingest a complete AnalysisResponse into multi-layer graph nodes', async () => {
    const mockAnalysis: AnalysisResponse = {
      analysisId: 'test-analysis-graph-1',
      url: 'https://security-verify-paypal.xyz/login',
      normalizedUrl: 'https://security-verify-paypal.xyz/login',
      verdict: 'PHISHING',
      riskScore: 92,
      riskLevel: 'CRITICAL',
      confidence: 0.98,
      mlProbability: 0.95,
      layers: {
        url: {
          status: 'SUCCESS',
          canonicalUrl: 'https://security-verify-paypal.xyz/login',
          hostname: 'security-verify-paypal.xyz',
          path: '/login',
          query: '',
          isShortener: false,
          isPunycode: false,
          hasUserInfo: false,
          hasCustomPort: false,
          obfuscatedEncodings: [],
          digitRatio: 0,
          specialCharRatio: 0.1,
          hyphenRatio: 0.2,
          entropy: 4.1,
          features: {
            url_length: 42,
            hostname_length: 27,
            path_length: 6,
            query_length: 0,
            subdomain_count: 2,
            has_ip_address: 0,
            has_https: 1,
            special_char_count: 3,
            digit_count: 0,
            hyphen_count: 2,
            at_symbol_count: 0,
            double_slash_in_path: 0,
            encoded_char_count: 0,
            suspicious_keyword_count: 2,
            entropy: 4.1,
            tld_in_subdomain: 0,
            port_in_url: 0,
            tld_length: 3
          }
        },
        domain: {
          status: 'SUCCESS',
          domain: 'security-verify-paypal.xyz',
          registrableDomain: 'security-verify-paypal.xyz',
          tld: 'xyz',
          subdomain: '',
          registrar: 'Namecheap, Inc.',
          creationDate: '2026-09-01T00:00:00Z',
          domainAgeDays: 5,
          domainAgeCategory: '< 30 days',
          isPrivacyProtected: true
        },
        dns: {
          status: 'SUCCESS',
          resolvedIps: ['185.220.101.5', '185.220.101.6'],
          ipv4Count: 2,
          ipv6Count: 0,
          nameservers: ['ns1.shadow-dns.com', 'ns2.shadow-dns.com'],
          mxRecords: [],
          cnameRecords: [],
          txtRecords: [],
          hasMx: false,
          ipDetails: [
            {
              ip: '185.220.101.5',
              version: 'IPv4',
              asn: 'AS200052',
              org: 'Bulletproof Host LLC',
              country: 'NL'
            }
          ]
        },
        tls: {
          status: 'SUCCESS',
          hasTls: true,
          certificateValid: true,
          certificateExpired: false,
          hostnameMatches: true,
          validFrom: '2026-09-01T00:00:00Z',
          validTo: '2026-12-01T00:00:00Z',
          daysUntilExpiry: 54,
          issuer: "Let's Encrypt",
          subject: 'security-verify-paypal.xyz',
          sans: ['security-verify-paypal.xyz'],
          zeroTrustWarning: 'Short-lived free certificate on new domain'
        },
        reputation: {
          status: 'SUCCESS',
          providers: [],
          isListedMalicious: true,
          reputationScore: 90
        },
        ml: {
          status: 'SUCCESS',
          phishingProbability: 0.95,
          confidence: 0.98,
          predictedLabel: 1,
          modelVersion: 'rf-v1.0',
          inferenceTimeMs: 12
        }
      },
      pageAnalysis: {
        status: 'COMPLETED',
        requestedUrl: 'https://security-verify-paypal.xyz/login',
        forms: [
          {
            action: 'https://evil-form-drop.com/steal.php',
            actionResolved: 'https://evil-form-drop.com/steal.php',
            method: 'POST',
            isCrossOrigin: true,
            isIpAction: false,
            hasPasswordField: true,
            hasEmailField: true,
            hasCreditCardField: false,
            hasOtpField: false,
            passwordFieldCount: 1,
            inputCount: 3
          }
        ],
        brandFindings: [
          {
            claimedBrand: 'PayPal',
            authenticDomain: 'paypal.com',
            actualDomain: 'security-verify-paypal.xyz',
            isMismatch: true,
            confidence: 0.99,
            matchSources: ['Title', 'DOM']
          }
        ],
        iframes: [],
        scripts: [],
        keywords: [],
        redirectCount: 0,
        redirectChain: [],
        urgencyScore: 80,
        contentRiskScore: 85,
        phishingProbability: 0.92,
        confidence: 0.98,
        acquisitionTimeMs: 250
      },
      evidence: [],
      createdAt: new Date().toISOString()
    };

    await ThreatGraphEngine.ingestAnalysis(mockAnalysis);

    // Verify sub-graph retrieval
    const subgraph = await ThreatGraphEngine.getDomainSubGraph('security-verify-paypal.xyz', 2);
    expect(subgraph.nodes.length).toBeGreaterThan(0);
    expect(subgraph.edges.length).toBeGreaterThan(0);

    const domainNode = subgraph.nodes.find((n) => n.id === 'domain:security-verify-paypal.xyz');
    expect(domainNode).toBeDefined();
    expect(domainNode?.type).toBe('DOMAIN');
    expect(domainNode?.riskScore).toBe(92);

    const brandNode = subgraph.nodes.find((n) => n.id === 'brand:paypal');
    expect(brandNode).toBeDefined();

    const asnNode = subgraph.nodes.find((n) => n.id === 'asn:AS200052');
    expect(asnNode).toBeDefined();
  });

  it('should generate valid STIX 2.1 JSON bundle from graph data', async () => {
    const subgraph = await ThreatGraphEngine.getDomainSubGraph('security-verify-paypal.xyz', 2);
    const bundle = STIXExportService.generateGraphSTIXBundle(subgraph);

    expect(bundle.type).toBe('bundle');
    expect(bundle.spec_version).toBe('2.1');
    expect(bundle.objects.length).toBeGreaterThan(0);
  });
});
