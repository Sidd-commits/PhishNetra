import {
  TyposquattingMatch,
  TyposquattingScanResult,
  RiskLevel
} from '@phishnetra/shared';

export interface TargetBrandCatalogItem {
  brand: string;
  officialDomain: string;
  keywords: string[];
}

export const TARGETED_BRANDS: TargetBrandCatalogItem[] = [
  { brand: 'Google', officialDomain: 'google.com', keywords: ['google', 'gmail', 'google-drive'] },
  { brand: 'Microsoft', officialDomain: 'microsoft.com', keywords: ['microsoft', 'office365', 'outlook', 'live', 'azure', 'sharepoint', 'onedrive'] },
  { brand: 'PayPal', officialDomain: 'paypal.com', keywords: ['paypal', 'pay-pal'] },
  { brand: 'Apple', officialDomain: 'apple.com', keywords: ['apple', 'icloud', 'appleid'] },
  { brand: 'Amazon', officialDomain: 'amazon.com', keywords: ['amazon', 'aws'] },
  { brand: 'Netflix', officialDomain: 'netflix.com', keywords: ['netflix'] },
  { brand: 'Meta / Facebook', officialDomain: 'facebook.com', keywords: ['facebook', 'fb', 'meta', 'instagram', 'whatsapp'] },
  { brand: 'Bank of America', officialDomain: 'bankofamerica.com', keywords: ['bankofamerica', 'bofa'] },
  { brand: 'Chase', officialDomain: 'chase.com', keywords: ['chase', 'chasebank'] },
  { brand: 'Wells Fargo', officialDomain: 'wellsfargo.com', keywords: ['wellsfargo'] },
  { brand: 'LinkedIn', officialDomain: 'linkedin.com', keywords: ['linkedin'] },
  { brand: 'Dropbox', officialDomain: 'dropbox.com', keywords: ['dropbox'] },
  { brand: 'Adobe', officialDomain: 'adobe.com', keywords: ['adobe'] },
  { brand: 'DHL Express', officialDomain: 'dhl.com', keywords: ['dhl', 'dhlexpress'] },
  { brand: 'Coinbase', officialDomain: 'coinbase.com', keywords: ['coinbase'] },
  { brand: 'Binance', officialDomain: 'binance.com', keywords: ['binance'] },
  { brand: 'DocuSign', officialDomain: 'docusign.com', keywords: ['docusign'] }
];

// Cyrillic & Greek homoglyphs mapping to ASCII lookalikes
const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', // cyrillic a
  '\u0441': 'c', // cyrillic c
  '\u0435': 'e', // cyrillic e
  '\u043E': 'o', // cyrillic o
  '\u0440': 'p', // cyrillic p
  '\u0455': 's', // cyrillic s
  '\u0456': 'i', // cyrillic i
  '\u0458': 'j', // cyrillic j
  '\u0443': 'y', // cyrillic y
  '\u0445': 'x', // cyrillic x
  '\u03B1': 'a', // greek alpha
  '\u03BF': 'o', // greek omicron
  '\u03BD': 'v', // greek nu
  '\u03C1': 'p', // greek rho
  '\u03C4': 't', // greek tau
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '5': 's',
  '8': 'b',
  'vv': 'w',
  'rn': 'm',
  'cl': 'd'
};

export class TyposquattingEngine {
  /**
   * Calculates Levenshtein Distance between two strings.
   */
  public static levenshtein(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }

    return matrix[b.length][a.length];
  }

  /**
   * Normalizes deceptive homoglyphs and confusable characters to standard ASCII.
   */
  public static normalizeHomoglyphs(str: string): { normalized: string; hasHomoglyphs: boolean } {
    let normalized = str.toLowerCase();
    let hasHomoglyphs = false;

    // First handle multi-char confusable combinations (rn -> m, vv -> w, cl -> d)
    if (normalized.includes('rn') || normalized.includes('vv') || normalized.includes('cl')) {
      hasHomoglyphs = true;
      normalized = normalized.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd');
    }

    let charArray = Array.from(normalized);
    for (let i = 0; i < charArray.length; i++) {
      const char = charArray[i];
      if (HOMOGLYPH_MAP[char]) {
        hasHomoglyphs = true;
        charArray[i] = HOMOGLYPH_MAP[char];
      }
    }

    return {
      normalized: charArray.join(''),
      hasHomoglyphs
    };
  }

  /**
   * Inspects a query domain against high-value brand catalogs to identify typosquatting attacks.
   */
  public static inspectDomain(domain: string): TyposquattingScanResult {
    const cleanDomain = domain.toLowerCase().trim();
    const domainWithoutTld = cleanDomain.split('.')[0];
    const { normalized: homoglyphNormalized, hasHomoglyphs } = this.normalizeHomoglyphs(cleanDomain);
    const normalizedWithoutTld = homoglyphNormalized.split('.')[0];

    const matches: TyposquattingMatch[] = [];
    let detectedBrand: string | null = null;
    let isDirectImpersonation = false;

    for (const brandItem of TARGETED_BRANDS) {
      const brandOfficialName = brandItem.officialDomain.split('.')[0];

      // Exact match with official domain -> Not an impersonation, it is legitimate
      if (cleanDomain === brandItem.officialDomain || cleanDomain.endsWith('.' + brandItem.officialDomain)) {
        continue;
      }

      // 1. Homoglyph Detection Check
      if (hasHomoglyphs && (normalizedWithoutTld === brandOfficialName || homoglyphNormalized.includes(brandOfficialName))) {
        detectedBrand = brandItem.brand;
        isDirectImpersonation = true;
        matches.push({
          variant: cleanDomain,
          targetBrand: brandItem.brand,
          officialDomain: brandItem.officialDomain,
          type: 'HOMOGLYPH',
          similarityScore: 98,
          riskLevel: 'CRITICAL',
          explanation: `Domain contains lookalike Cyrillic/Greek homoglyphs or visual glyph substitutions imitating official '${brandItem.officialDomain}'.`
        });
        continue;
      }

      // 2. Combosquatting Check (e.g. paypal-security-login.com or apple-id-verify.com)
      const securityKeywords = ['login', 'signin', 'verify', 'account', 'security', 'secure', 'auth', 'update', 'portal', 'support', 'wallet'];
      const hasBrandKeyword = brandItem.keywords.some((kw) => domainWithoutTld.includes(kw));
      const hasSecKeyword = securityKeywords.some((kw) => domainWithoutTld.includes(kw));

      if (hasBrandKeyword && hasSecKeyword && cleanDomain !== brandItem.officialDomain) {
        detectedBrand = brandItem.brand;
        isDirectImpersonation = true;
        matches.push({
          variant: cleanDomain,
          targetBrand: brandItem.brand,
          officialDomain: brandItem.officialDomain,
          type: 'COMBOSQUAT',
          similarityScore: 92,
          riskLevel: 'HIGH',
          explanation: `Combosquatting detected: Target blends brand trademark '${brandItem.brand}' with security keyword in unapproved domain '${cleanDomain}'.`
        });
        continue;
      }

      // 3. Subdomain Deception Check (e.g. paypal.com.attacker-domain.com)
      if (cleanDomain.startsWith(brandOfficialName + '.') || cleanDomain.includes('.' + brandOfficialName + '.')) {
        detectedBrand = brandItem.brand;
        isDirectImpersonation = true;
        matches.push({
          variant: cleanDomain,
          targetBrand: brandItem.brand,
          officialDomain: brandItem.officialDomain,
          type: 'SUBDOMAIN',
          similarityScore: 95,
          riskLevel: 'CRITICAL',
          explanation: `Subdomain deception: Subdomain mimics brand '${brandOfficialName}' under unrelated parent domain.`
        });
        continue;
      }

      // 4. Levenshtein Distance Check (Typo / Omission / Transposition)
      const distance = this.levenshtein(domainWithoutTld, brandOfficialName);
      if (distance === 1 || (distance === 2 && domainWithoutTld.length > 5)) {
        const similarity = Math.max(0, Math.round((1 - distance / Math.max(domainWithoutTld.length, brandOfficialName.length)) * 100));
        detectedBrand = brandItem.brand;
        isDirectImpersonation = true;
        matches.push({
          variant: cleanDomain,
          targetBrand: brandItem.brand,
          officialDomain: brandItem.officialDomain,
          type: distance === 1 ? 'LEVENSHTEIN' : 'OMISSION',
          distance,
          similarityScore: similarity,
          riskLevel: distance === 1 ? 'HIGH' : 'MEDIUM',
          explanation: `High character proximity to brand '${brandItem.brand}' (${brandItem.officialDomain}) with Levenshtein edit distance of ${distance}.`
        });
      }
    }

    return {
      queryDomain: cleanDomain,
      detectedTargetBrand: detectedBrand,
      isDirectImpersonation,
      totalVariantsGenerated: matches.length,
      matches
    };
  }

  /**
   * Proactively generates simulated typosquatting permutations for security testing & intelligence.
   */
  public static generatePermutations(domain: string): TyposquattingMatch[] {
    const cleanDomain = domain.toLowerCase().trim();
    const parts = cleanDomain.split('.');
    const sld = parts[0];
    const tld = parts.slice(1).join('.') || 'com';
    const variants: TyposquattingMatch[] = [];

    // Omission variants (skip one character)
    for (let i = 0; i < sld.length; i++) {
      const variantSld = sld.slice(0, i) + sld.slice(i + 1);
      if (variantSld.length >= 3) {
        variants.push({
          variant: `${variantSld}.${tld}`,
          targetBrand: sld.toUpperCase(),
          officialDomain: cleanDomain,
          type: 'OMISSION',
          distance: 1,
          similarityScore: 85,
          riskLevel: 'MEDIUM',
          explanation: `Single character omission permutation: omitted '${sld[i]}' at index ${i}`
        });
      }
    }

    // Repetition variants (double character)
    for (let i = 0; i < sld.length; i++) {
      const variantSld = sld.slice(0, i + 1) + sld[i] + sld.slice(i + 1);
      variants.push({
        variant: `${variantSld}.${tld}`,
        targetBrand: sld.toUpperCase(),
        officialDomain: cleanDomain,
        type: 'REPETITION',
        distance: 1,
        similarityScore: 88,
        riskLevel: 'MEDIUM',
        explanation: `Character repetition permutation: repeated '${sld[i]}'`
      });
    }

    // Homoglyph permutations (Cyrillic a -> \u0430, o -> \u043E, e -> \u0435)
    let homoglyphSld = sld.replace(/a/g, '\u0430').replace(/o/g, '\u043E').replace(/e/g, '\u0435');
    if (homoglyphSld !== sld) {
      variants.push({
        variant: `${homoglyphSld}.${tld}`,
        targetBrand: sld.toUpperCase(),
        officialDomain: cleanDomain,
        type: 'HOMOGLYPH',
        distance: 1,
        similarityScore: 96,
        riskLevel: 'CRITICAL',
        explanation: 'Deceptive Cyrillic Unicode character substitution permutation'
      });
    }

    return variants.slice(0, 15);
  }
}
