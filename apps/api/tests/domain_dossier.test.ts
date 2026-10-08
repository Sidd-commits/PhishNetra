import { domainService } from '../src/services/DomainService';

describe('Domain Dossier & Threat Hub Suite', () => {
  it('should generate a comprehensive domain dossier with typosquatting alerts', async () => {
    const dossier = await domainService.getDomainDossier('google.com');

    expect(dossier).toBeDefined();
    expect(dossier.domain).toBe('google.com');
    expect(dossier.registrableDomain).toBe('google.com');
    expect(typeof dossier.riskScore).toBe('number');
    expect(Array.isArray(dossier.nameservers)).toBe(true);
    expect(Array.isArray(dossier.typosquattingAlerts)).toBe(true);
    expect(dossier.typosquattingAlerts.length).toBeGreaterThan(0);
  });

  it('should analyze typosquatting variations on demand', () => {
    const result = domainService.analyzeTyposquatting('paypal.com');
    expect(result.queryDomain).toBe('paypal.com');
    expect(Array.isArray(result.permutations)).toBe(true);
    expect(result.permutations.length).toBeGreaterThan(0);
  });
});
