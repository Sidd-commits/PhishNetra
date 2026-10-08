import {
  TAXIICollection,
  TAXIIDiscovery
} from '@phishnetra/shared';

export class TaxiiServerService {
  private static instance: TaxiiServerService;

  private collections: TAXIICollection[] = [
    {
      id: 'col-verified-phishing',
      title: 'PhishNetra Verified Zero-Trust Phishing IOCs',
      description: 'High-confidence zero-day phishing domains, drop-boxes, and JA3 fingerprints validated by 8-layer engine.',
      canRead: true,
      canWrite: false,
      mediaTypes: ['application/taxii+json;version=2.1', 'application/stix+json;version=2.1'],
      objectsCount: 1420
    },
    {
      id: 'col-adversary-campaigns',
      title: 'Active Adversary Infrastructure Campaigns',
      description: 'Clustered STIX 2.1 threat campaign entities, associated nameservers, ASNs, and target brands.',
      canRead: true,
      canWrite: false,
      mediaTypes: ['application/taxii+json;version=2.1', 'application/stix+json;version=2.1'],
      objectsCount: 88
    },
    {
      id: 'col-honeypot-canaries',
      title: 'Canary Deception Tripwire Hits',
      description: 'Active indicators derived from triggered canary web bugs and synthetic honeypot interactions.',
      canRead: true,
      canWrite: false,
      mediaTypes: ['application/taxii+json;version=2.1', 'application/stix+json;version=2.1'],
      objectsCount: 312
    }
  ];

  public static getInstance(): TaxiiServerService {
    if (!TaxiiServerService.instance) {
      TaxiiServerService.instance = new TaxiiServerService();
    }
    return TaxiiServerService.instance;
  }

  public getDiscovery(): TAXIIDiscovery {
    return {
      title: 'PhishNetra Enterprise TAXII 2.1 Server',
      description: 'Zero-Trust Automated Phishing & Cyber Threat Intelligence Sharing Hub',
      contact: 'secops-intel@phishnetra.security',
      defaultApiRoot: 'https://api.phishnetra.security/api/taxii21',
      apiRoots: ['https://api.phishnetra.security/api/taxii21']
    };
  }

  public listCollections(): TAXIICollection[] {
    return this.collections;
  }

  public getCollection(id: string): TAXIICollection | null {
    return this.collections.find(c => c.id === id) || null;
  }

  public getStixObjects(collectionId: string): any {
    const now = new Date().toISOString();
    return {
      type: 'bundle',
      id: `bundle--${Date.now()}`,
      objects: [
        {
          type: 'indicator',
          spec_version: '2.1',
          id: 'indicator--9f82a1c0-4411-4a88-bf12-984401a8ef11',
          created: now,
          modified: now,
          name: 'Verified Phishing Domain: auth-sec-verify-microsoft.account-portal.xyz',
          description: 'High-confidence credential harvesting targeting Microsoft corporate users.',
          pattern: "[url:value = 'https://auth-sec-verify-microsoft.account-portal.xyz/login']",
          pattern_type: 'stix',
          valid_from: now,
          labels: ['phishing', 'zero-trust-confirmed', 'credential-harvest']
        },
        {
          type: 'threat-actor',
          spec_version: '2.1',
          id: 'threat-actor--7a12b9c3-1122-4a99-bf33-128801b9ef22',
          created: now,
          modified: now,
          name: 'UNC-Phish-Syndicate-94',
          threat_actor_types: ['cybercriminal'],
          aliases: ['Velvet Harvester']
        }
      ]
    };
  }
}

export const taxiiServerService = TaxiiServerService.getInstance();
