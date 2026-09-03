import { URLIntelligence, EvidenceItem, URLFeatureVector } from '@phishnetra/shared';
import { CanonicalUrlResult } from './canonicalization';

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'cutt.ly',
  'rb.gy', 'shorturl.at', 'rebrand.ly', 'goo.gl', 'trib.al', 'cli.re'
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'cc', 'club', 'work', 'click', 'live', 'loan', 'gq', 'cf',
  'tk', 'ml', 'ga', 'buzz', 'racing', 'icu', 'fit', 'rest'
]);

const SUSPICIOUS_PORTS = new Set([8080, 8443, 8888, 8000, 9000, 2082, 2083, 2086, 2087]);

export class URLLayer {
  /**
   * Analyzes structural, lexical, and security-oriented URL characteristics.
   */
  public analyze(canonical: CanonicalUrlResult, deterministicFeatures?: URLFeatureVector): {
    data: URLIntelligence;
    evidence: EvidenceItem[];
  } {
    const evidence: EvidenceItem[] = [];
    const { canonicalUrl, hostname, pathname, search, port, isPunycode, unicodeHostname } = canonical;

    const isShortener = KNOWN_SHORTENERS.has(hostname);
    const shortenerProvider = isShortener ? hostname : null;

    // Check userinfo (e.g. http://user@attacker.com)
    const hasUserInfo = canonical.rawUrl.includes('@') && !search.includes('@');
    if (hasUserInfo) {
      evidence.push({
        layer: 'URL',
        featureKey: 'userinfo_in_url',
        featureValue: 'true',
        severity: 'HIGH',
        description: 'URL contains "@" user-info credentials prefix, a known trick to obscure the destination host.',
        contribution: 0.25,
        source: 'URL_Intelligence',
        confidence: 0.95
      });
    }

    if (isShortener) {
      evidence.push({
        layer: 'URL',
        featureKey: 'url_shortener_detected',
        featureValue: hostname,
        severity: 'MEDIUM',
        description: `URL uses shortening provider (${hostname}), hiding the true target domain.`,
        contribution: 0.15,
        source: 'URL_Intelligence',
        confidence: 0.90
      });
    }

    if (isPunycode) {
      evidence.push({
        layer: 'URL',
        featureKey: 'punycode_hostname',
        featureValue: unicodeHostname || hostname,
        severity: 'HIGH',
        description: `Internationalized domain name (Punycode: ${hostname}) detected, often used in homoglyph visual spoofing.`,
        contribution: 0.30,
        source: 'URL_Intelligence',
        confidence: 0.95
      });
    }

    // Custom port check
    const hasCustomPort = port !== null && SUSPICIOUS_PORTS.has(port);
    if (hasCustomPort) {
      evidence.push({
        layer: 'URL',
        featureKey: 'suspicious_port',
        featureValue: port,
        severity: 'HIGH',
        description: `URL connects to non-standard HTTP port ${port}, an anomalous pattern for authentic web services.`,
        contribution: 0.20,
        source: 'URL_Intelligence',
        confidence: 0.90
      });
    }

    // Obfuscated hex encodings
    const obfuscatedEncodings: string[] = [];
    const hexMatches = canonical.rawUrl.match(/%(2F|40|3A|20|25|3D|26)/gi);
    if (hexMatches) {
      obfuscatedEncodings.push(...Array.from(new Set(hexMatches.map(m => m.toUpperCase()))));
      evidence.push({
        layer: 'URL',
        featureKey: 'obfuscated_hex_sequences',
        featureValue: obfuscatedEncodings.join(', '),
        severity: 'MEDIUM',
        description: `URL contains encoded structural delimiters (${obfuscatedEncodings.join(', ')}), a common filter-bypass mechanism.`,
        contribution: 0.15,
        source: 'URL_Intelligence',
        confidence: 0.85
      });
    }

    // Lexical ratios
    const totalLen = Math.max(1, canonicalUrl.length);
    const digitCount = (canonicalUrl.match(/\d/g) || []).length;
    const specialCount = (canonicalUrl.match(/[@\-_=?%&*!~+]/g) || []).length;
    const hyphenCount = (hostname.match(/-/g) || []).length;

    const digitRatio = Math.round((digitCount / totalLen) * 1000) / 1000;
    const specialCharRatio = Math.round((specialCount / totalLen) * 1000) / 1000;
    const hyphenRatio = Math.round((hyphenCount / Math.max(1, hostname.length)) * 1000) / 1000;

    // TLD Suspiciousness
    const hostParts = hostname.split('.');
    const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';
    if (SUSPICIOUS_TLDS.has(tld)) {
      evidence.push({
        layer: 'URL',
        featureKey: 'high_risk_tld',
        featureValue: `.${tld}`,
        severity: 'MEDIUM',
        description: `Domain utilizes top-level domain (.${tld}) statistically correlated with high abuse and disposable campaigns.`,
        contribution: 0.15,
        source: 'URL_Intelligence',
        confidence: 0.80
      });
    }

    // Fallback default features if not passed from ML
    const features: URLFeatureVector = deterministicFeatures || {
      url_length: canonicalUrl.length,
      hostname_length: hostname.length,
      path_length: pathname.length,
      query_length: search.length,
      subdomain_count: Math.max(0, hostParts.length - 2),
      has_ip_address: /(\d{1,3}\.){3}\d{1,3}/.test(hostname) ? 1 : 0,
      has_https: canonical.protocol === 'https:' ? 1 : 0,
      special_char_count: specialCount,
      digit_count: digitCount,
      hyphen_count: hyphenCount,
      at_symbol_count: hasUserInfo ? 1 : 0,
      double_slash_in_path: pathname.includes('//') ? 1 : 0,
      encoded_char_count: obfuscatedEncodings.length,
      suspicious_keyword_count: 0,
      entropy: 3.5,
      tld_in_subdomain: 0,
      port_in_url: port ? 1 : 0,
      tld_length: tld.length
    };

    return {
      data: {
        status: 'SUCCESS',
        canonicalUrl,
        hostname,
        path: pathname,
        query: search,
        isShortener,
        shortenerProvider,
        isPunycode,
        unicodeHostname,
        hasUserInfo,
        hasCustomPort,
        customPort: port,
        obfuscatedEncodings,
        digitRatio,
        specialCharRatio,
        hyphenRatio,
        entropy: features.entropy,
        features
      },
      evidence
    };
  }
}

export const urlLayer = new URLLayer();
