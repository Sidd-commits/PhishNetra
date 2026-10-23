import { riskEngine } from '../src/services/RiskEngine';
import { canonicalizeUrl } from '../src/services/analysis/canonicalization';
import { urlLayer } from '../src/services/analysis/urlLayer';
import {
  extractDomainParts,
  RISK_THRESHOLDS,
  URLIntelligence,
  DomainIntelligence,
  DNSIntelligence,
  TLSIntelligence,
  ReputationIntelligence,
  MLIntelligence,
  PageAnalysisResult,
  EvidenceItem
} from '@phishnetra/shared';

describe('Phase 8: Detection Optimization & Regression Suite', () => {

  describe('1. URL Canonicalization & Multi-Part ccTLD Parsing', () => {
    it('should correctly parse multi-part ccTLDs without splitting registrable domain incorrectly', () => {
      const ukDomain = extractDomainParts('news.bbc.co.uk');
      expect(ukDomain.registrableDomain).toBe('bbc.co.uk');
      expect(ukDomain.tld).toBe('co.uk');
      expect(ukDomain.subdomain).toBe('news');

      const inDomain = extractDomainParts('maps.google.co.in');
      expect(inDomain.registrableDomain).toBe('google.co.in');
      expect(inDomain.tld).toBe('co.in');
      expect(inDomain.subdomain).toBe('maps');

      const standardDomain = extractDomainParts('gemini.google.com');
      expect(standardDomain.registrableDomain).toBe('google.com');
      expect(standardDomain.tld).toBe('com');
      expect(standardDomain.subdomain).toBe('gemini');
    });

    it('should handle bare URLs and trailing dots consistently', () => {
      const canonical1 = canonicalizeUrl('gemini.google.com');
      expect(canonical1.protocol).toBe('http:');
      expect(canonical1.hostname).toBe('gemini.google.com');
      expect(canonical1.canonicalUrl).toBe('http://gemini.google.com/');

      const canonical2 = canonicalizeUrl('https://gemini.google.com./');
      expect(canonical2.hostname).toBe('gemini.google.com');
      expect(canonical2.canonicalUrl).toBe('https://gemini.google.com/');
    });

    it('should distinguish RFC 3986 userinfo credential @ from query parameter email addresses', () => {
      // Query param email (legitimate sign-in redirect)
      const legitimateSsoUrl = 'https://accounts.google.com/signin?continue=https://gemini.google.com&Email=user@example.com';
      const canonicalLegit = canonicalizeUrl(legitimateSsoUrl);
      expect(canonicalLegit.hasUserInfo).toBe(false);

      const legitAnalysis = urlLayer.analyze(canonicalLegit);
      expect(legitAnalysis.data.hasUserInfo).toBe(false);
      expect(legitAnalysis.evidence.some(e => e.featureKey === 'userinfo_in_url')).toBe(false);

      // Malicious userinfo obfuscation (user@attacker.com)
      const attackerUrl = 'http://support%40google.com:token@evil-phishing-host.xyz/auth';
      const canonicalAttacker = canonicalizeUrl(attackerUrl);
      expect(canonicalAttacker.hasUserInfo).toBe(true);

      const attackerAnalysis = urlLayer.analyze(canonicalAttacker);
      expect(attackerAnalysis.data.hasUserInfo).toBe(true);
      expect(attackerAnalysis.evidence.some(e => e.featureKey === 'userinfo_in_url')).toBe(true);
    });
  });

  describe('2. URL Layer Analysis & Threat Evidence', () => {
    it('should classify Google Gemini URL with 0 critical threat indicators', () => {
      const canonical = canonicalizeUrl('https://gemini.google.com/app');
      const result = urlLayer.analyze(canonical);

      expect(result.data.isShortener).toBe(false);
      expect(result.data.isPunycode).toBe(false);
      expect(result.data.hasUserInfo).toBe(false);
      expect(result.data.hasCustomPort).toBe(false);
      expect(result.evidence.length).toBe(0);
    });

    it('should flag Punycode homoglyph spoofing authentic brands with CRITICAL severity', () => {
      const canonical = canonicalizeUrl('http://xn--ggle-55da.com/login.html');
      const result = urlLayer.analyze(canonical);

      expect(result.data.isPunycode).toBe(true);
      const homoglyphEvidence = result.evidence.find(e => e.featureKey === 'homoglyph_brand_spoofing');
      expect(homoglyphEvidence).toBeDefined();
      expect(homoglyphEvidence?.severity).toBe('CRITICAL');
      expect(homoglyphEvidence?.contribution).toBeGreaterThanOrEqual(0.40);
    });

    it('should identify high-abuse disposable TLDs', () => {
      const canonical = canonicalizeUrl('http://paypal.com.account-update.xyz/login');
      const result = urlLayer.analyze(canonical);

      const tldEvidence = result.evidence.find(e => e.featureKey === 'high_risk_tld');
      expect(tldEvidence).toBeDefined();
      expect(tldEvidence?.featureValue).toBe('.xyz');
    });
  });

  describe('3. Multi-Layer Decision Engine & Zero-Trust Overrides', () => {
    const baseLegitFeatures = {
      url_length: 24,
      hostname_length: 17,
      path_length: 4,
      query_length: 0,
      subdomain_count: 1,
      has_ip_address: 0,
      has_https: 1,
      special_char_count: 0,
      digit_count: 0,
      hyphen_count: 0,
      at_symbol_count: 0,
      double_slash_in_path: 0,
      encoded_char_count: 0,
      suspicious_keyword_count: 0,
      entropy: 3.6,
      tld_in_subdomain: 0,
      port_in_url: 0,
      tld_length: 3
    };

    it('should classify Google Gemini as SAFE with LOW risk score via brand dampener', () => {
      const urlLayerData: URLIntelligence = {
        status: 'SUCCESS',
        canonicalUrl: 'https://gemini.google.com/app',
        hostname: 'gemini.google.com',
        path: '/app',
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
        specialCharRatio: 0,
        hyphenRatio: 0,
        entropy: 3.6,
        features: baseLegitFeatures
      };

      const domainLayerData: DomainIntelligence = {
        status: 'SUCCESS',
        domain: 'gemini.google.com',
        registrableDomain: 'google.com',
        tld: 'com',
        subdomain: 'gemini',
        registrar: 'MarkMonitor, Inc.',
        creationDate: '1997-09-15T04:00:00Z',
        expirationDate: '2028-09-14T04:00:00Z',
        domainAgeDays: 9800,
        domainAgeCategory: '> 365 days',
        isPrivacyProtected: false
      };

      const dnsLayerData: DNSIntelligence = {
        status: 'SUCCESS',
        resolvedIps: ['142.250.190.46'],
        ipv4Count: 1,
        ipv6Count: 0,
        nameservers: ['ns1.google.com', 'ns2.google.com'],
        mxRecords: ['smtp.google.com'],
        cnameRecords: [],
        txtRecords: [],
        hasMx: true,
        ipDetails: [{ ip: '142.250.190.46', version: 'IPv4', asn: 'AS15169', org: 'GOOGLE', country: 'US' }]
      };

      const tlsLayerData: TLSIntelligence = {
        status: 'SUCCESS',
        hasTls: true,
        issuer: 'Google Trust Services LLC',
        subject: 'CN=*.google.com',
        validFrom: '2026-01-01',
        validTo: '2026-12-31',
        daysUntilExpiry: 180,
        certificateValid: true,
        certificateExpired: false,
        hostnameMatches: true,
        sans: ['*.google.com'],
        tlsVersion: 'TLSv1.3',
        zeroTrustWarning: 'Transport valid'
      };

      const reputationLayerData: ReputationIntelligence = {
        status: 'SUCCESS',
        isListedMalicious: false,
        reputationScore: 0,
        providers: []
      };

      const mlLayerData: MLIntelligence = {
        status: 'SUCCESS',
        phishingProbability: 0.016,
        confidence: 0.98,
        predictedLabel: 0,
        modelVersion: 'v1.0.0-optimized',
        inferenceTimeMs: 14.5
      };

      const pageLayerData: PageAnalysisResult = {
        status: 'COMPLETED',
        requestedUrl: 'https://gemini.google.com/app',
        finalUrl: 'https://gemini.google.com/app',
        redirectCount: 0,
        redirectChain: [],
        forms: [],
        iframes: [{ src: '', isCrossOrigin: false, isHidden: true }],
        scripts: [],
        keywords: [],
        brandFindings: [
          {
            claimedBrand: 'Google',
            authenticDomain: 'google.com',
            actualDomain: 'google.com',
            isMismatch: false,
            confidence: 0.95,
            matchSources: ['Title contains Google']
          }
        ],
        urgencyScore: 0.0,
        contentRiskScore: 5.0,
        phishingProbability: 0.05,
        confidence: 0.92,
        error: null,
        blockReason: null,
        acquisitionTimeMs: 250
      };

      const evalResult = riskEngine.evaluateMultiLayer({
        urlLayer: urlLayerData,
        domainLayer: domainLayerData,
        dnsLayer: dnsLayerData,
        tlsLayer: tlsLayerData,
        reputationLayer: reputationLayerData,
        mlLayer: mlLayerData,
        pageLayer: pageLayerData,
        layerEvidences: []
      });

      expect(evalResult.verdict).toBe('SAFE');
      expect(evalResult.riskLevel).toBe('LOW');
      expect(evalResult.riskScore).toBeLessThan(RISK_THRESHOLDS.SAFE_MAX);
      expect(evalResult.riskScore).toBeLessThanOrEqual(18.0);
    });

    it('should force Zero-Trust PHISHING override on homoglyph brand spoofing', () => {
      const homoglyphEvidence: EvidenceItem = {
        layer: 'URL',
        featureKey: 'homoglyph_brand_spoofing',
        featureValue: 'gооgle.com',
        severity: 'CRITICAL',
        description: 'Homoglyph visual spoofing attack targeting authentic brand detected',
        contribution: 0.45,
        source: 'URL_Intelligence',
        confidence: 0.95
      };

      const evalResult = riskEngine.evaluateMultiLayer({
        urlLayer: {
          status: 'SUCCESS',
          canonicalUrl: 'http://xn--gogle-pqa.com/login.html',
          hostname: 'xn--gogle-pqa.com',
          path: '/login.html',
          query: '',
          isShortener: false,
          shortenerProvider: null,
          isPunycode: true,
          unicodeHostname: 'gооgle.com',
          hasUserInfo: false,
          hasCustomPort: false,
          customPort: null,
          obfuscatedEncodings: [],
          digitRatio: 0,
          specialCharRatio: 0,
          hyphenRatio: 0,
          entropy: 3.8,
          features: { ...baseLegitFeatures, hyphen_count: 2 }
        },
        domainLayer: {
          status: 'SUCCESS',
          domain: 'xn--gogle-pqa.com',
          registrableDomain: 'xn--gogle-pqa.com',
          tld: 'com',
          subdomain: '',
          registrar: 'NameCheap, Inc.',
          creationDate: '2026-10-01T00:00:00Z',
          expirationDate: '2027-10-01T00:00:00Z',
          domainAgeDays: 5,
          domainAgeCategory: '< 30 days',
          isPrivacyProtected: true
        },
        dnsLayer: {
          status: 'SUCCESS',
          resolvedIps: ['198.51.100.99'],
          ipv4Count: 1,
          ipv6Count: 0,
          nameservers: ['ns1.evilhost.com'],
          mxRecords: [],
          cnameRecords: [],
          txtRecords: [],
          hasMx: false,
          ipDetails: []
        },
        tlsLayer: {
          status: 'SUCCESS',
          hasTls: false,
          issuer: null,
          subject: null,
          validFrom: null,
          validTo: null,
          daysUntilExpiry: null,
          certificateValid: false,
          certificateExpired: false,
          hostnameMatches: false,
          sans: [],
          tlsVersion: null,
          zeroTrustWarning: 'No TLS active'
        },
        reputationLayer: {
          status: 'SUCCESS',
          isListedMalicious: false,
          reputationScore: 0,
          providers: []
        },
        mlLayer: {
          status: 'SUCCESS',
          phishingProbability: 0.967,
          confidence: 0.93,
          predictedLabel: 1,
          modelVersion: 'v1.0.0-optimized',
          inferenceTimeMs: 12.0
        },
        layerEvidences: [homoglyphEvidence]
      });

      expect(evalResult.verdict).toBe('PHISHING');
      expect(evalResult.riskLevel).toBe('CRITICAL');
      expect(evalResult.riskScore).toBeGreaterThanOrEqual(85.0);
    });

    it('should force Zero-Trust PHISHING override on combosquatting with high-abuse TLD', () => {
      const highTldEvidence: EvidenceItem = {
        layer: 'URL',
        featureKey: 'high_risk_tld',
        featureValue: '.xyz',
        severity: 'MEDIUM',
        description: 'Domain utilizes top-level domain (.xyz) correlated with high abuse',
        contribution: 0.20,
        source: 'URL_Intelligence',
        confidence: 0.85
      };

      const evalResult = riskEngine.evaluateMultiLayer({
        urlLayer: {
          status: 'SUCCESS',
          canonicalUrl: 'http://paypal.com.account-update.xyz/login',
          hostname: 'paypal.com.account-update.xyz',
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
          specialCharRatio: 0,
          hyphenRatio: 0.05,
          entropy: 4.1,
          features: { ...baseLegitFeatures, tld_in_subdomain: 1 }
        },
        domainLayer: {
          status: 'SUCCESS',
          domain: 'account-update.xyz',
          registrableDomain: 'account-update.xyz',
          tld: 'xyz',
          subdomain: 'paypal.com',
          registrar: 'Hostinger, UAB',
          creationDate: '2026-10-10T00:00:00Z',
          expirationDate: '2027-10-10T00:00:00Z',
          domainAgeDays: 12,
          domainAgeCategory: '< 30 days',
          isPrivacyProtected: true
        },
        dnsLayer: {
          status: 'SUCCESS',
          resolvedIps: ['198.51.100.42'],
          ipv4Count: 1,
          ipv6Count: 0,
          nameservers: [],
          mxRecords: [],
          cnameRecords: [],
          txtRecords: [],
          hasMx: false,
          ipDetails: []
        },
        tlsLayer: {
          status: 'SUCCESS',
          hasTls: false,
          issuer: null,
          subject: null,
          validFrom: null,
          validTo: null,
          daysUntilExpiry: null,
          certificateValid: false,
          certificateExpired: false,
          hostnameMatches: false,
          sans: [],
          tlsVersion: null,
          zeroTrustWarning: 'No TLS active'
        },
        reputationLayer: {
          status: 'SUCCESS',
          isListedMalicious: false,
          reputationScore: 0,
          providers: []
        },
        mlLayer: {
          status: 'SUCCESS',
          phishingProbability: 0.98,
          confidence: 0.96,
          predictedLabel: 1,
          modelVersion: 'v1.0.0-optimized',
          inferenceTimeMs: 15.0
        },
        layerEvidences: [highTldEvidence]
      });

      expect(evalResult.verdict).toBe('PHISHING');
      expect(evalResult.riskScore).toBeGreaterThanOrEqual(80.0);
    });

    it('should classify Internshala with app store references and same-origin login as SAFE with LOW risk score', () => {
      const evalResult = riskEngine.evaluateMultiLayer({
        urlLayer: {
          status: 'SUCCESS',
          canonicalUrl: 'https://internshala.com/chat/c-125923166?filter=all',
          hostname: 'internshala.com',
          path: '/chat/c-125923166',
          query: 'filter=all',
          isShortener: false,
          shortenerProvider: null,
          isPunycode: false,
          unicodeHostname: null,
          hasUserInfo: false,
          hasCustomPort: false,
          customPort: null,
          obfuscatedEncodings: [],
          digitRatio: 0,
          specialCharRatio: 0,
          hyphenRatio: 0,
          entropy: 3.2,
          features: {
            url_length: 53,
            hostname_length: 15,
            path_length: 17,
            query_length: 10,
            subdomain_count: 0,
            has_ip_address: 0,
            has_https: 1,
            special_char_count: 5,
            digit_count: 9,
            hyphen_count: 1,
            at_symbol_count: 0,
            double_slash_in_path: 0,
            encoded_char_count: 0,
            suspicious_keyword_count: 0,
            entropy: 3.2,
            tld_in_subdomain: 0,
            port_in_url: 0,
            tld_length: 3
          }
        },
        domainLayer: {
          status: 'SUCCESS',
          domain: 'internshala.com',
          registrableDomain: 'internshala.com',
          tld: 'com',
          subdomain: '',
          registrar: 'GoDaddy',
          creationDate: '2010-09-01T00:00:00Z',
          expirationDate: '2028-09-01T00:00:00Z',
          domainAgeDays: 5200,
          domainAgeCategory: '> 365 days',
          isPrivacyProtected: false,
          rawStatus: 'ACTIVE'
        },
        dnsLayer: {
          status: 'SUCCESS',
          resolvedIps: ['104.26.12.34', '104.26.13.34'],
          ipv4Count: 2,
          ipv6Count: 2,
          nameservers: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
          mxRecords: ['aspmx.l.google.com'],
          cnameRecords: [],
          txtRecords: [],
          hasMx: true,
          ipDetails: []
        },
        tlsLayer: {
          status: 'SUCCESS',
          hasTls: true,
          issuer: 'Cloudflare Inc ECC CA-3',
          subject: 'internshala.com',
          validFrom: '2026-01-01',
          validTo: '2027-01-01',
          daysUntilExpiry: 180,
          certificateValid: true,
          certificateExpired: false,
          hostnameMatches: true,
          sans: ['internshala.com', '*.internshala.com'],
          tlsVersion: 'TLSv1.3',
          zeroTrustWarning: 'Transport valid'
        },
        reputationLayer: {
          status: 'SUCCESS',
          isListedMalicious: false,
          reputationScore: 0,
          providers: []
        },
        mlLayer: {
          status: 'SUCCESS',
          phishingProbability: 0.031,
          confidence: 0.97,
          predictedLabel: 0,
          modelVersion: 'v1.0.0-optimized',
          inferenceTimeMs: 12.0
        },
        pageLayer: {
          status: 'COMPLETED',
          requestedUrl: 'https://internshala.com/chat/c-125923166?filter=all',
          finalUrl: 'https://internshala.com/chat/c-125923166?filter=all',
          redirectCount: 0,
          redirectChain: [],
          forms: [
            {
              id: 'login_form',
              name: 'login',
              action: '/login-user',
              actionResolved: 'https://internshala.com/login-user',
              method: 'POST',
              target: '',
              isCrossOrigin: false,
              isIpAction: false,
              hasPasswordField: true,
              hasEmailField: true,
              hasCreditCardField: false,
              hasOtpField: false,
              passwordFieldCount: 1,
              inputCount: 2,
              description: 'Internshala user login form'
            }
          ],
          iframes: [{ src: 'https://www.googletagmanager.com/ns.html', isCrossOrigin: true, isHidden: true }],
          scripts: [],
          keywords: [],
          brandFindings: [],
          urgencyScore: 0.0,
          contentRiskScore: 5.0,
          phishingProbability: 0.05,
          confidence: 0.90,
          error: null,
          blockReason: null,
          acquisitionTimeMs: 320
        },
        layerEvidences: []
      });

      expect(evalResult.verdict).toBe('SAFE');
      expect(evalResult.riskLevel).toBe('LOW');
      expect(evalResult.riskScore).toBeLessThan(RISK_THRESHOLDS.SAFE_MAX);
    });

    it('should classify accredited College ERP portal with student login form as SAFE with LOW risk score', () => {
      const evalResult = riskEngine.evaluateMultiLayer({
        urlLayer: {
          status: 'SUCCESS',
          canonicalUrl: 'https://erp.iitd.ac.in/login',
          hostname: 'erp.iitd.ac.in',
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
          specialCharRatio: 0,
          hyphenRatio: 0,
          entropy: 3.1,
          features: {
            url_length: 27,
            hostname_length: 14,
            path_length: 6,
            query_length: 0,
            subdomain_count: 1,
            has_ip_address: 0,
            has_https: 1,
            special_char_count: 3,
            digit_count: 0,
            hyphen_count: 0,
            at_symbol_count: 0,
            double_slash_in_path: 0,
            encoded_char_count: 0,
            suspicious_keyword_count: 1,
            entropy: 3.1,
            tld_in_subdomain: 0,
            port_in_url: 0,
            tld_length: 5
          }
        },
        domainLayer: {
          status: 'SUCCESS',
          domain: 'erp.iitd.ac.in',
          registrableDomain: 'iitd.ac.in',
          tld: 'ac.in',
          subdomain: 'erp',
          registrar: 'ERNET India',
          creationDate: '2000-01-01T00:00:00Z',
          expirationDate: '2030-01-01T00:00:00Z',
          domainAgeDays: 9000,
          domainAgeCategory: '> 365 days',
          isPrivacyProtected: false,
          rawStatus: 'ACTIVE'
        },
        dnsLayer: {
          status: 'SUCCESS',
          resolvedIps: ['14.139.45.10'],
          ipv4Count: 1,
          ipv6Count: 0,
          nameservers: ['ns1.iitd.ac.in', 'ns2.iitd.ac.in'],
          mxRecords: ['mail.iitd.ac.in'],
          cnameRecords: [],
          txtRecords: [],
          hasMx: true,
          ipDetails: []
        },
        tlsLayer: {
          status: 'SUCCESS',
          hasTls: true,
          issuer: 'DigiCert Global Root CA',
          subject: 'erp.iitd.ac.in',
          validFrom: '2026-01-01',
          validTo: '2027-01-01',
          daysUntilExpiry: 200,
          certificateValid: true,
          certificateExpired: false,
          hostnameMatches: true,
          sans: ['erp.iitd.ac.in', '*.iitd.ac.in'],
          tlsVersion: 'TLSv1.3',
          zeroTrustWarning: 'Transport valid'
        },
        reputationLayer: {
          status: 'SUCCESS',
          isListedMalicious: false,
          reputationScore: 0,
          providers: []
        },
        mlLayer: {
          status: 'SUCCESS',
          phishingProbability: 0.018,
          confidence: 0.98,
          predictedLabel: 0,
          modelVersion: 'v1.0.0-optimized',
          inferenceTimeMs: 11.0
        },
        pageLayer: {
          status: 'COMPLETED',
          requestedUrl: 'https://erp.iitd.ac.in/login',
          finalUrl: 'https://erp.iitd.ac.in/login',
          redirectCount: 0,
          redirectChain: [],
          forms: [
            {
              id: 'student_auth',
              name: 'loginForm',
              action: '/auth/verify',
              actionResolved: 'https://erp.iitd.ac.in/auth/verify',
              method: 'POST',
              target: '',
              isCrossOrigin: false,
              isIpAction: false,
              hasPasswordField: true,
              hasEmailField: true,
              hasCreditCardField: false,
              hasOtpField: false,
              passwordFieldCount: 1,
              inputCount: 2,
              description: 'IIT Delhi Student and Staff login form'
            }
          ],
          iframes: [],
          scripts: [],
          keywords: [],
          brandFindings: [],
          urgencyScore: 0.0,
          contentRiskScore: 5.0,
          phishingProbability: 0.05,
          confidence: 0.92,
          error: null,
          blockReason: null,
          acquisitionTimeMs: 280
        },
        layerEvidences: []
      });

      expect(evalResult.verdict).toBe('SAFE');
      expect(evalResult.riskLevel).toBe('LOW');
      expect(evalResult.riskScore).toBeLessThanOrEqual(24.0);
    });
  });

  describe('4. Threshold Boundary Determinism', () => {
    it('should map score boundaries consistently according to documented policy', () => {
      // 0 <= score <= 34.99 -> SAFE (LOW)
      // 35.0 <= score <= 69.99 -> SUSPICIOUS (MEDIUM)
      // 70.0 <= score <= 79.99 -> PHISHING (HIGH)
      // 80.0 <= score <= 100 -> PHISHING (CRITICAL)

      expect(RISK_THRESHOLDS.SAFE_MAX).toBe(34.99);
      expect(RISK_THRESHOLDS.SUSPICIOUS_MAX).toBe(69.99);
      expect(RISK_THRESHOLDS.HIGH_MAX).toBe(79.99);
    });
  });
});
