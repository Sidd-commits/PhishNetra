/**
 * PhishNetra Extension — Local Lexical & Heuristics Engine
 * 
 * Provides instantaneous (<5ms) client-side lexical risk scoring to protect users
 * before full backend multi-tier pipeline completes.
 */

import { extractDomainParts } from '@phishnetra/shared';

export interface LocalHeuristicResult {
  score: number; // 0 to 100
  isSuspicious: boolean;
  isLikelyPhishing: boolean;
  reasons: string[];
  entropy: number;
  indicators: {
    ipHostname: boolean;
    excessiveSubdomains: boolean;
    suspiciousTld: boolean;
    homoglyphOrPunycode: boolean;
    credentialKeywords: boolean;
    excessiveLength: boolean;
    atSymbolPresent: boolean;
    suspiciousPort: boolean;
  };
}

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'cf', 'gq', 'buzz', 'fit', 'icu',
  'rest', 'click', 'live', 'work', 'loan', 'racing', 'surf', 'online',
  'cam', 'monster', 'beauty', 'hair', 'press', 'quest'
]);

const BRAND_KEYWORDS = [
  'paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix', 'chase', 'wellsfargo', 'bankofamerica'
];

const GENERIC_CREDENTIAL_KEYWORDS = [
  'login', 'signin', 'secure', 'verify', 'account', 'update', 'wallet',
  'billing', 'security', 'authentication', 'recovery', 'passcode', 'credential'
];

/**
 * Calculates Shannon entropy of a string
 */
export function calculateEntropy(str: string): number {
  if (!str) return 0;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

/**
 * Evaluates local lexical heuristics on given URL
 */
export function evaluateLocalHeuristics(rawUrl: string): LocalHeuristicResult {
  const reasons: string[] = [];
  let score = 0;

  const indicators = {
    ipHostname: false,
    excessiveSubdomains: false,
    suspiciousTld: false,
    homoglyphOrPunycode: false,
    credentialKeywords: false,
    excessiveLength: false,
    atSymbolPresent: false,
    suspiciousPort: false
  };

  try {
    const safeUrl = (rawUrl.startsWith('http://') || rawUrl.startsWith('https://'))
      ? rawUrl
      : 'https://' + rawUrl;
    const urlObj = new URL(safeUrl);
    const hostname = urlObj.hostname.toLowerCase();

    // 1. IP Address as Hostname check
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(hostname)) {
      indicators.ipHostname = true;
      score += 45;
      reasons.push('Raw IP address used as hostname instead of domain name');
    }

    // 2. Punycode / Homoglyph check
    if (hostname.includes('xn--')) {
      indicators.homoglyphOrPunycode = true;
      score += 40;
      reasons.push('Internationalized/Punycode domain (potential Cyrillic/homoglyph spoofing)');
    }

    // Domain and TLD extraction
    const { registrableDomain, tld, subdomain } = extractDomainParts(hostname);
    const subdomains = subdomain ? subdomain.split('.').filter(p => p && p !== 'www') : [];

    // 3. Suspicious TLD check
    if (SUSPICIOUS_TLDS.has(tld)) {
      indicators.suspiciousTld = true;
      score += 25;
      reasons.push(`High-abuse Top-Level Domain detected (.${tld})`);
    }

    // 4. Excessive Subdomains check (e.g. paypal.security.login.attacker.com)
    if (subdomains.length >= 3) {
      indicators.excessiveSubdomains = true;
      score += 30;
      reasons.push(`Excessive subdomains (${subdomains.length}) detected`);
    }

    // 5. Credential/Phishing Keywords & Combosquatting
    // Brand keywords appearing in subdomains of a different registrable domain
    const suspiciousBrandSpoof = BRAND_KEYWORDS.some(b => 
      (subdomain.includes(b) && !registrableDomain.includes(b))
    );
    if (suspiciousBrandSpoof) {
      indicators.credentialKeywords = true;
      score += 40;
      reasons.push(`Brand name found in subdomain of unrelated domain (${registrableDomain})`);
    }

    // Multiple generic credential keywords crammed into hostname
    const matchedGeneric = GENERIC_CREDENTIAL_KEYWORDS.filter(kw => hostname.includes(kw));
    if (matchedGeneric.length >= 2 && !suspiciousBrandSpoof) {
      indicators.credentialKeywords = true;
      score += Math.min(30, matchedGeneric.length * 15);
      reasons.push(`Multiple security/credential keywords present in domain (${matchedGeneric.join(', ')})`);
    }

    // 6. High Shannon Entropy in hostname
    const entropy = calculateEntropy(hostname);
    if (entropy > 3.9 && hostname.length > 20) {
      score += 20;
      reasons.push(`High lexical entropy (${entropy}) suggesting algorithmically generated or randomized domain`);
    }

    // 7. Presence of '@' in userinfo authority (RFC 3986 trick)
    const hasUserInfoAt = Boolean(urlObj.username || urlObj.password);
    if (hasUserInfoAt) {
      indicators.atSymbolPresent = true;
      score += 35;
      reasons.push('Contains RFC 3986 userinfo credentials prefix "@" used to mislead browser URL parser');
    }

    // 8. Excessive URL length (only flag truly abnormal lengths > 250 chars)
    if (rawUrl.length > 250 || hostname.length > 50) {
      indicators.excessiveLength = true;
      score += 15;
      reasons.push(`Abnormally long URL length (${rawUrl.length} characters)`);
    }

    // 9. Non-standard HTTP ports (e.g. :8080, :8888, :8443, :9000, :4444)
    if (urlObj.port && !['80', '443', '3000', '5000', '5173', '8000'].includes(urlObj.port)) {
      indicators.suspiciousPort = true;
      score += 20;
      reasons.push(`Non-standard network port detected (:${urlObj.port})`);
    }

    // Normalize final score to max 100
    const finalScore = Math.min(100, score);

    return {
      score: finalScore,
      isSuspicious: finalScore >= 35,
      isLikelyPhishing: finalScore >= 70,
      reasons,
      entropy,
      indicators
    };
  } catch (err) {
    return {
      score: 0,
      isSuspicious: false,
      isLikelyPhishing: false,
      reasons: ['Invalid URL string'],
      entropy: 0,
      indicators
    };
  }
}
