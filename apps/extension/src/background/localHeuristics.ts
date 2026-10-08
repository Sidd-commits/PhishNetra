/**
 * PhishNetra Extension — Local Lexical & Heuristics Engine
 * 
 * Provides instantaneous (<5ms) client-side lexical risk scoring to protect users
 * before full backend multi-tier pipeline completes.
 */

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

const HIGH_RISK_KEYWORDS = [
  'paypal', 'bank', 'login', 'signin', 'secure', 'verify', 'account',
  'update', 'wallet', 'metamask', 'crypto', 'billing', 'support',
  'security', 'authentication', 'recovery', 'passcode', 'credential',
  'webscr', 'ebayisapi', 'banking', 'confirm', 'portal'
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
    const urlObj = new URL(rawUrl);
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

    // 3. Suspicious TLD check
    const parts = hostname.split('.');
    const tld = parts.length > 1 ? parts[parts.length - 1] : '';
    if (SUSPICIOUS_TLDS.has(tld)) {
      indicators.suspiciousTld = true;
      score += 25;
      reasons.push(`High-abuse Top-Level Domain detected (.${tld})`);
    }

    // 4. Excessive Subdomains check (e.g. paypal.security.login.attacker.com)
    // Filter out standard 'www'
    const subdomains = parts.filter(p => p !== 'www' && p !== tld);
    if (subdomains.length >= 3) {
      indicators.excessiveSubdomains = true;
      score += 30;
      reasons.push(`Excessive subdomains (${subdomains.length}) detected`);
    }

    // 5. Credential/Phishing Keywords in Hostname & Subdomain
    const matchedKeywords: string[] = [];
    for (const kw of HIGH_RISK_KEYWORDS) {
      if (hostname.includes(kw)) {
        matchedKeywords.push(kw);
      }
    }
    if (matchedKeywords.length > 0) {
      indicators.credentialKeywords = true;
      // If keyword is in subdomain of a different base domain, highly suspicious
      score += Math.min(35, matchedKeywords.length * 20);
      reasons.push(`Security/credential keywords present in domain (${matchedKeywords.join(', ')})`);
    }

    // 6. High Shannon Entropy in hostname
    const entropy = calculateEntropy(hostname);
    if (entropy > 3.8 && hostname.length > 15) {
      score += 20;
      reasons.push(`High lexical entropy (${entropy}) suggesting algorithmically generated or randomized domain`);
    }

    // 7. Presence of '@' symbol (often used to obscure real host)
    if (rawUrl.includes('@')) {
      indicators.atSymbolPresent = true;
      score += 35;
      reasons.push('Contains "@" character used to mislead browser URL parser');
    }

    // 8. Excessive URL length
    if (rawUrl.length > 100) {
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
      isSuspicious: finalScore >= 40,
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
