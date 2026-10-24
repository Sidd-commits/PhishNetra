import { URLIntelligence, EvidenceItem, URLFeatureVector, extractDomainParts } from '@phishnetra/shared';
import { CanonicalUrlResult } from './canonicalization';
import { TyposquattingEngine } from './typosquatting';

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'cutt.ly',
  'rb.gy', 'shorturl.at', 'rebrand.ly', 'goo.gl', 'trib.al', 'cli.re'
]);

const DYNAMIC_DNS_DOMAINS = new Set([
  'duckdns.org', 'no-ip.biz', 'no-ip.com', 'no-ip.org',
  'ngrok-free.app', 'ngrok.io', 'free-ddns.com', 'ddns.net',
  'zapto.org', 'hopto.org', 'servehttp.com', 'dynu.net', 'bounceme.net'
]);

const FREE_CLOUD_HOSTING_PROVIDERS = new Set([
  'vercel.app', 'pages.dev', 'framer.app', 'netlify.app',
  'workers.dev', 'web.app', 'firebaseapp.com', 'glitch.me',
  'render.com', 'surge.sh', 'herokuapp.com'
]);

const SENSITIVE_LURE_KEYWORDS = new Set([
  'auth', 'login', 'signin', 'admin', 'verify', 'account', 'security',
  'portal', 'wallet', 'bank', 'token', 'session', 'update', 'recover', 'support'
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'cc', 'club', 'work', 'click', 'live', 'loan', 'gq', 'cf',
  'tk', 'ml', 'ga', 'buzz', 'racing', 'icu', 'fit', 'rest'
]);

const SUSPICIOUS_PORTS = new Set([8080, 8443, 8888, 8000, 9000, 2082, 2083, 2086, 2087]);

const TARGETED_BRANDS = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'netflix', 'chase', 'wellsfargo', 'bankofamerica'];

const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', '\u0441': 'c', '\u0434': 'd', '\u0435': 'e', '\u0456': 'i',
  '\u0458': 'j', '\u043a': 'k', '\u043e': 'o', '\u0440': 'p', '\u0455': 's',
  '\u0442': 't', '\u0443': 'y', '\u0445': 'x', '\u03bf': 'o', '\u03b1': 'a',
  '\u03c1': 'p', '\u03bd': 'v', '\u03b5': 'e', '\u03b9': 'i'
};

function normalizeHomoglyphs(text: string): string {
  const decomposed = text.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  return decomposed.split('').map(c => HOMOGLYPH_MAP[c] || c).join('');
}

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

    // Check RFC 3986 userinfo credential prefix (e.g. http://user@attacker.com)
    const hasUserInfo = canonical.hasUserInfo;
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

    // Dynamic DNS & Ephemeral Tunneling Detection
    const { registrableDomain, tld, subdomain } = extractDomainParts(hostname);
    const isDynamicDns = DYNAMIC_DNS_DOMAINS.has(registrableDomain) || Array.from(DYNAMIC_DNS_DOMAINS).some(d => hostname.endsWith('.' + d));
    if (isDynamicDns) {
      evidence.push({
        layer: 'URL',
        featureKey: 'dynamic_dns_tunnel',
        featureValue: registrableDomain,
        severity: 'HIGH',
        description: `Domain utilizes a Dynamic DNS or ephemeral tunneling provider (${registrableDomain}), frequently abused for unverified phishing infrastructure.`,
        contribution: 0.25,
        source: 'URL_Intelligence',
        confidence: 0.90
      });
    }

    // Free Cloud PaaS & Ephemeral Subdomain Detection
    const isFreeCloudHosting = FREE_CLOUD_HOSTING_PROVIDERS.has(registrableDomain) || Array.from(FREE_CLOUD_HOSTING_PROVIDERS).some(d => hostname.endsWith('.' + d));
    if (isFreeCloudHosting && subdomain) {
      const subTokens = subdomain.toLowerCase().split(/[.-]/).filter(Boolean);
      const pathTokens = (pathname || '').toLowerCase().split(/[\/._-]/).filter(Boolean);
      const allTokens = [...subTokens, ...pathTokens];
      const matchedLure = allTokens.find(token => SENSITIVE_LURE_KEYWORDS.has(token));

      if (matchedLure) {
        evidence.push({
          layer: 'URL',
          featureKey: 'cloud_subdomain_credential_lure',
          featureValue: `${registrableDomain} / ${matchedLure}`,
          severity: 'HIGH',
          description: `Free cloud hosting tenant URL contains sensitive authentication keyword ("${matchedLure}"), a common technique for staging unverified phishing campaigns.`,
          contribution: 0.35,
          source: 'URL_Intelligence',
          confidence: 0.90
        });
      }

      // Check for ephemeral, disposable, or machine-generated slug pattern
      const hyphenSegments = subdomain.split('-');
      const hasDigitGroup = /\d{4,}/.test(subdomain);
      const isEphemeralSlug = hyphenSegments.length >= 3 || (hyphenSegments.length >= 2 && hasDigitGroup) || /^[a-z0-9]{12,}$/i.test(subdomain);
      if (isEphemeralSlug) {
        evidence.push({
          layer: 'URL',
          featureKey: 'ephemeral_cloud_subdomain',
          featureValue: subdomain,
          severity: 'MEDIUM',
          description: `Subdomain exhibits a machine-generated or ephemeral tenant slug pattern (${subdomain}) on a free cloud hosting provider (${registrableDomain}).`,
          contribution: 0.25,
          source: 'URL_Intelligence',
          confidence: 0.85
        });
      }
    }

    // Advanced Typosquatting, Combosquatting, and Homoglyph Inspection
    const cleanLookup = unicodeHostname || hostname;
    const typoScan = TyposquattingEngine.inspectDomain(cleanLookup);
    if (typoScan && typoScan.matches && typoScan.matches.length > 0) {
      for (const match of typoScan.matches) {
        if (match.type === 'HOMOGLYPH') {
          evidence.push({
            layer: 'URL',
            featureKey: 'homoglyph_brand_spoofing',
            featureValue: cleanLookup,
            severity: 'CRITICAL',
            description: match.explanation,
            contribution: 0.45,
            source: 'URL_TyposquattingEngine',
            confidence: 0.95
          });
        } else if (match.type === 'COMBOSQUAT') {
          evidence.push({
            layer: 'URL',
            featureKey: 'combosquatting_brand_impersonation',
            featureValue: cleanLookup,
            severity: 'HIGH',
            description: match.explanation,
            contribution: 0.40,
            source: 'URL_TyposquattingEngine',
            confidence: 0.90
          });
        } else if (match.type === 'SUBDOMAIN') {
          evidence.push({
            layer: 'URL',
            featureKey: 'subdomain_brand_deception',
            featureValue: cleanLookup,
            severity: 'CRITICAL',
            description: match.explanation,
            contribution: 0.45,
            source: 'URL_TyposquattingEngine',
            confidence: 0.95
          });
        } else {
          evidence.push({
            layer: 'URL',
            featureKey: 'typosquatting_brand_spoofing',
            featureValue: cleanLookup,
            severity: 'CRITICAL',
            description: match.explanation,
            contribution: 0.40,
            source: 'URL_TyposquattingEngine',
            confidence: 0.92
          });
        }
      }
    } else if (isPunycode) {
      const decoded = unicodeHostname || hostname;
      const normalizedDecoded = normalizeHomoglyphs(decoded);
      const isTargetingBrand = TARGETED_BRANDS.some(b => normalizedDecoded.includes(b));
      evidence.push({
        layer: 'URL',
        featureKey: isTargetingBrand ? 'homoglyph_brand_spoofing' : 'punycode_hostname',
        featureValue: decoded,
        severity: isTargetingBrand ? 'CRITICAL' : 'HIGH',
        description: isTargetingBrand
          ? `Homoglyph visual spoofing attack targeting authentic brand detected via Punycode domain (${decoded}).`
          : `Internationalized domain name (Punycode: ${hostname}) detected, often used in homoglyph visual spoofing.`,
        contribution: isTargetingBrand ? 0.45 : 0.30,
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

    // Subdomain count
    const subdomainParts = subdomain ? subdomain.split('.').filter(p => p && p !== 'www') : [];
    const subdomainCount = subdomainParts.length;

    // TLD Suspiciousness
    if (SUSPICIOUS_TLDS.has(tld)) {
      evidence.push({
        layer: 'URL',
        featureKey: 'high_risk_tld',
        featureValue: `.${tld}`,
        severity: 'MEDIUM',
        description: `Domain utilizes top-level domain (.${tld}) statistically correlated with high abuse and disposable campaigns.`,
        contribution: 0.20,
        source: 'URL_Intelligence',
        confidence: 0.85
      });
    }

    // Fallback default features if not passed from ML
    const features: URLFeatureVector = deterministicFeatures || {
      url_length: canonicalUrl.length,
      hostname_length: hostname.length,
      path_length: pathname.length,
      query_length: search.length,
      subdomain_count: subdomainCount,
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
