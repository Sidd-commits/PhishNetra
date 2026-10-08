import { CampaignClusteringEngine } from '../src/services/graph/CampaignClusteringEngine';
import { ThreatGraphEngine } from '../src/services/graph/ThreatGraphEngine';
import { STIXExportService } from '../src/services/graph/STIXExportService';

describe('Threat Campaign Clustering Suite', () => {
  beforeAll(async () => {
    // Seed 3 domains sharing the same ASN, Nameserver, and Brand Target
    const d1 = await ThreatGraphEngine.upsertNode('domain:paypaI-security-check.xyz', 'paypaI-security-check.xyz', 'DOMAIN', {}, 90, 'CRITICAL');
    const d2 = await ThreatGraphEngine.upsertNode('domain:paypaI-account-recovery.xyz', 'paypaI-account-recovery.xyz', 'DOMAIN', {}, 85, 'CRITICAL');
    const d3 = await ThreatGraphEngine.upsertNode('domain:paypaI-billing-verify.xyz', 'paypaI-billing-verify.xyz', 'DOMAIN', {}, 88, 'CRITICAL');

    const asn = await ThreatGraphEngine.upsertNode('asn:AS99999', 'AS99999', 'ASN', { org: 'ShadowHost LLC' });
    const ip = await ThreatGraphEngine.upsertNode('ip:198.51.100.22', '198.51.100.22', 'IP', {});
    const ns = await ThreatGraphEngine.upsertNode('ns:ns1.bulletproof-dns.cc', 'ns1.bulletproof-dns.cc', 'NAMESERVER', {});
    const brand = await ThreatGraphEngine.upsertNode('brand:paypal', 'PayPal', 'BRAND', {});

    // Link shared infrastructure
    for (const d of [d1, d2, d3]) {
      await ThreatGraphEngine.upsertEdge(d.id, ip.id, 'RESOLVES_TO');
      await ThreatGraphEngine.upsertEdge(ip.id, asn.id, 'HOSTED_ON');
      await ThreatGraphEngine.upsertEdge(d.id, ns.id, 'MANAGED_BY_NS');
      await ThreatGraphEngine.upsertEdge(d.id, brand.id, 'IMPERSONATES');
    }
  });

  it('should cluster infrastructure sharing domains into a unified ThreatCampaign', async () => {
    const result = await CampaignClusteringEngine.runClustering();
    expect(result).toBeDefined();
    expect(result.totalCampaigns).toBeGreaterThanOrEqual(1);

    const campaigns = await CampaignClusteringEngine.listCampaigns();
    expect(campaigns.length).toBeGreaterThanOrEqual(1);

    const paypalCampaign = campaigns.find((c) => c.targetedBrands.includes('PayPal') || c.name.includes('PayPal'));
    expect(paypalCampaign).toBeDefined();
    expect(paypalCampaign?.iocs.domains.length).toBeGreaterThanOrEqual(1);
    expect(paypalCampaign?.status).toBe('ACTIVE');
  });

  it('should export campaign in valid STIX 2.1 JSON bundle format', async () => {
    const campaigns = await CampaignClusteringEngine.listCampaigns();
    const campaign = campaigns[0];
    expect(campaign).toBeDefined();

    const stix = STIXExportService.generateCampaignSTIXBundle(campaign);
    expect(stix.type).toBe('bundle');
    expect(stix.spec_version).toBe('2.1');
    expect(stix.objects.some((o: any) => o.type === 'campaign')).toBe(true);
    expect(stix.objects.some((o: any) => o.type === 'indicator')).toBe(true);
  });
});
