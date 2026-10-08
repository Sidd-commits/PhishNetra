import axios from 'axios';
import { DomainIntelligence, EvidenceItem } from '@phishnetra/shared';
import { cache, CacheManager } from '../cache/CacheManager';

export class DomainLayer {
  /**
   * Extracts domain breakdown and retrieves RDAP registration metadata.
   */
  public async analyze(hostname: string): Promise<{
    data: DomainIntelligence;
    evidence: EvidenceItem[];
  }> {
    const evidence: EvidenceItem[] = [];

    // Check if hostname is raw IP
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
    if (isIp) {
      return {
        data: {
          status: 'SKIPPED',
          domain: hostname,
          registrableDomain: hostname,
          tld: '',
          subdomain: '',
          registrar: null,
          creationDate: null,
          expirationDate: null,
          domainAgeDays: null,
          domainAgeCategory: 'unknown',
          isPrivacyProtected: false,
          rawStatus: 'Target is a raw IP address; domain registration skipped'
        },
        evidence: []
      };
    }

    // Parse domain parts
    const { domain, registrableDomain, tld, subdomain } = this.parseDomainParts(hostname);

    const cacheKey = `domain:${registrableDomain}`;
    return cache.wrap(cacheKey, async () => {
      return this.fetchDomainIntel(hostname, domain, registrableDomain, tld, subdomain);
    }, CacheManager.TTL.RDAP_DOMAIN);
  }

  private async fetchDomainIntel(
    hostname: string,
    domain: string,
    registrableDomain: string,
    tld: string,
    subdomain: string
  ): Promise<{ data: DomainIntelligence; evidence: EvidenceItem[] }> {
    const evidence: EvidenceItem[] = [];
    let registrar: string | null = null;
    let creationDate: string | null = null;
    let expirationDate: string | null = null;
    let domainAgeDays: number | null = null;
    let domainAgeCategory: '< 30 days' | '30–90 days' | '90–365 days' | '> 365 days' | 'unknown' = 'unknown';
    let isPrivacyProtected = false;
    let layerStatus: 'SUCCESS' | 'PARTIAL' | 'UNAVAILABLE' = 'SUCCESS';

    try {
      // Query RDAP bootstrap gateway with strict 2500ms timeout
      const response = await axios.get(`https://rdap.org/domain/${registrableDomain}`, {
        timeout: 2500,
        headers: { Accept: 'application/rdap+json, application/json' }
      });

      const rdap = response.data;

      // Extract events
      if (Array.isArray(rdap.events)) {
        for (const evt of rdap.events) {
          if (evt.eventAction === 'registration') {
            creationDate = evt.eventDate;
          } else if (evt.eventAction === 'expiration') {
            expirationDate = evt.eventDate;
          }
        }
      }

      // Extract registrar name
      if (Array.isArray(rdap.entities)) {
        for (const entity of rdap.entities) {
          if (Array.isArray(entity.roles) && entity.roles.includes('registrar')) {
            registrar = entity.vcardArray?.[1]?.find((item: any) => item[0] === 'fn')?.[3] || entity.handle || null;
          }
          if (JSON.stringify(entity).toLowerCase().includes('privacy') || JSON.stringify(entity).toLowerCase().includes('proxy')) {
            isPrivacyProtected = true;
          }
        }
      }

      // Compute domain age in days
      if (creationDate) {
        const createdMs = new Date(creationDate).getTime();
        const nowMs = Date.now();
        if (!isNaN(createdMs) && createdMs <= nowMs) {
          domainAgeDays = Math.floor((nowMs - createdMs) / (1000 * 60 * 60 * 24));

          if (domainAgeDays < 30) {
            domainAgeCategory = '< 30 days';
            evidence.push({
              layer: 'DOMAIN',
              featureKey: 'newly_registered_domain',
              featureValue: `${domainAgeDays} days`,
              severity: 'HIGH',
              description: `Domain was created ${domainAgeDays} days ago (< 30 days). Newly registered domains have high statistical correlation with disposable phishing campaigns.`,
              contribution: 0.35,
              source: 'RDAP',
              confidence: 0.90
            });
          } else if (domainAgeDays < 90) {
            domainAgeCategory = '30–90 days';
            evidence.push({
              layer: 'DOMAIN',
              featureKey: 'young_domain',
              featureValue: `${domainAgeDays} days`,
              severity: 'MEDIUM',
              description: `Domain is relatively young (${domainAgeDays} days old).`,
              contribution: 0.15,
              source: 'RDAP',
              confidence: 0.85
            });
          } else if (domainAgeDays < 365) {
            domainAgeCategory = '90–365 days';
          } else {
            domainAgeCategory = '> 365 days';
            evidence.push({
              layer: 'DOMAIN',
              featureKey: 'established_domain',
              featureValue: `${Math.floor(domainAgeDays / 365)} years (${domainAgeDays} days)`,
              severity: 'INFO',
              description: `Domain has established history (${domainAgeDays} days old).`,
              contribution: 0.0,
              source: 'RDAP',
              confidence: 0.95
            });
          }
        }
      }
    } catch {
      // RDAP unavailable, rate limited, or domain not supported by RDAP bootstrap
      layerStatus = 'PARTIAL';
      domainAgeCategory = 'unknown';
      evidence.push({
        layer: 'DOMAIN',
        featureKey: 'rdap_registration_unavailable',
        featureValue: 'UNAVAILABLE',
        severity: 'LOW',
        description: 'Domain registration registry information was unavailable or rate-limited; analysis continued with remaining layers.',
        contribution: 0.05,
        source: 'RDAP',
        confidence: 0.70
      });
    }

    const result: DomainIntelligence = {
      status: layerStatus,
      domain,
      registrableDomain,
      tld,
      subdomain,
      registrar,
      creationDate,
      expirationDate,
      domainAgeDays,
      domainAgeCategory,
      isPrivacyProtected
    };

    return { data: result, evidence };
  }

  private parseDomainParts(hostname: string): {
    domain: string;
    registrableDomain: string;
    tld: string;
    subdomain: string;
  } {
    const parts = hostname.toLowerCase().split('.');
    if (parts.length <= 1) {
      return { domain: hostname, registrableDomain: hostname, tld: '', subdomain: '' };
    }

    const tld = parts[parts.length - 1];

    // Handle common double TLDs (e.g. co.uk, com.au, co.in)
    let registrableDomain = hostname;
    let subdomain = '';

    if (parts.length >= 3 && ['co', 'com', 'org', 'net', 'edu', 'gov'].includes(parts[parts.length - 2])) {
      registrableDomain = parts.slice(-3).join('.');
      subdomain = parts.slice(0, -3).join('.');
    } else if (parts.length >= 2) {
      registrableDomain = parts.slice(-2).join('.');
      subdomain = parts.slice(0, -2).join('.');
    }

    return {
      domain: hostname,
      registrableDomain,
      tld,
      subdomain
    };
  }
}

export const domainLayer = new DomainLayer();
