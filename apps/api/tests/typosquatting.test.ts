import { TyposquattingEngine } from '../src/services/analysis/typosquatting';

describe('Typosquatting & Homoglyph Threat Engine', () => {
  it('should accurately calculate Levenshtein edit distance', () => {
    expect(TyposquattingEngine.levenshtein('google', 'goggle')).toBe(1);
    expect(TyposquattingEngine.levenshtein('paypal', 'paypall')).toBe(1);
    expect(TyposquattingEngine.levenshtein('microsoft', 'rnicrosoft')).toBe(2);
    expect(TyposquattingEngine.levenshtein('apple', 'apple')).toBe(0);
  });

  it('should normalize and detect Cyrillic lookalike homoglyphs', () => {
    // Cyrillic 'а' (\u0430) in 'pаypal'
    const deceptive = 'p\u0430ypal.com';
    const { normalized, hasHomoglyphs } = TyposquattingEngine.normalizeHomoglyphs(deceptive);

    expect(hasHomoglyphs).toBe(true);
    expect(normalized).toBe('paypal.com');

    const result = TyposquattingEngine.inspectDomain(deceptive);
    expect(result.isDirectImpersonation).toBe(true);
    expect(result.detectedTargetBrand).toBe('PayPal');
    expect(result.matches.some((m) => m.type === 'HOMOGLYPH')).toBe(true);
  });

  it('should detect combosquatting targeting high-value brands', () => {
    const deceptive = 'paypal-security-update.com';
    const result = TyposquattingEngine.inspectDomain(deceptive);

    expect(result.isDirectImpersonation).toBe(true);
    expect(result.detectedTargetBrand).toBe('PayPal');
    expect(result.matches.some((m) => m.type === 'COMBOSQUAT')).toBe(true);
  });

  it('should detect subdomain brand deception tricks', () => {
    const deceptive = 'microsoft.com.account-verify-login.xyz';
    const result = TyposquattingEngine.inspectDomain(deceptive);

    expect(result.isDirectImpersonation).toBe(true);
    expect(result.detectedTargetBrand).toBe('Microsoft');
    expect(result.matches.some((m) => m.type === 'SUBDOMAIN')).toBe(true);
  });

  it('should not flag official brand domains as typosquats', () => {
    const legit1 = TyposquattingEngine.inspectDomain('google.com');
    expect(legit1.isDirectImpersonation).toBe(false);

    const legit2 = TyposquattingEngine.inspectDomain('paypal.com');
    expect(legit2.isDirectImpersonation).toBe(false);
  });

  it('should generate simulated lookalike permutations for security analysis', () => {
    const permutations = TyposquattingEngine.generatePermutations('netflix.com');
    expect(permutations.length).toBeGreaterThan(0);
    expect(permutations.some((p) => p.type === 'OMISSION')).toBe(true);
    expect(permutations.some((p) => p.type === 'REPETITION')).toBe(true);
  });
});
