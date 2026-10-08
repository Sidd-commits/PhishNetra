import { evaluateLocalHeuristics, calculateEntropy } from '../src/background/localHeuristics';

describe('Local Lexical Heuristics Engine', () => {
  it('should calculate accurate Shannon entropy for strings', () => {
    expect(calculateEntropy('')).toBe(0);
    expect(calculateEntropy('aaaa')).toBe(0);
    const lowEntropy = calculateEntropy('google.com');
    const highEntropy = calculateEntropy('q9z8x7c6v5b4a3s2d1f0.xyz');
    expect(highEntropy).toBeGreaterThan(lowEntropy);
  });

  it('should detect raw IP address hostname as high risk', () => {
    const result = evaluateLocalHeuristics('http://192.168.1.100/login/secure');
    expect(result.indicators.ipHostname).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(45);
    expect(result.isSuspicious).toBe(true);
  });

  it('should detect punycode / homoglyph characters', () => {
    const result = evaluateLocalHeuristics('https://xn--pple-43d.com/login');
    expect(result.indicators.homoglyphOrPunycode).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(40);
  });

  it('should flag suspicious TLDs and excessive subdomains', () => {
    const result = evaluateLocalHeuristics('https://paypal.verification.security.user.attacker.xyz/update');
    expect(result.indicators.suspiciousTld).toBe(true);
    expect(result.indicators.excessiveSubdomains).toBe(true);
    expect(result.indicators.credentialKeywords).toBe(true);
    expect(result.isLikelyPhishing).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(70);
  });

  it('should flag @ symbol present in URL', () => {
    const result = evaluateLocalHeuristics('https://google.com@evil-phish-domain.com');
    expect(result.indicators.atSymbolPresent).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(35);
  });

  it('should return benign score for standard clean domain', () => {
    const result = evaluateLocalHeuristics('https://github.com/Sidd-commits/PhishNetra');
    expect(result.indicators.ipHostname).toBe(false);
    expect(result.indicators.suspiciousTld).toBe(false);
    expect(result.indicators.homoglyphOrPunycode).toBe(false);
    expect(result.isLikelyPhishing).toBe(false);
  });

  it('should handle invalid URLs gracefully without throwing', () => {
    const result = evaluateLocalHeuristics('not-a-valid-url');
    expect(result.score).toBe(0);
    expect(result.isLikelyPhishing).toBe(false);
  });
});
