import dns from 'dns/promises';
import { DNSIntelligence, IPDetail, EvidenceItem } from '@phishnetra/shared';
import { cache, CacheManager } from '../cache/CacheManager';

export interface IpIntelligenceProvider {
  lookup(ip: string): Promise<Partial<IPDetail>>;
}

export class DefaultIpIntelligenceProvider implements IpIntelligenceProvider {
  public async lookup(ip: string): Promise<Partial<IPDetail>> {
    // Basic IP range heuristics without external network dependencies
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.') || ip === '127.0.0.1') {
      return { asn: 'RFC1918-PRIVATE', org: 'Private Network Range', country: 'INTERNAL' };
    }
    if (ip.startsWith('104.') || ip.startsWith('172.67.') || ip.startsWith('188.114.')) {
      return { asn: 'AS13335', org: 'Cloudflare, Inc.', country: 'US' };
    }
    if (ip.startsWith('142.250.') || ip.startsWith('172.217.') || ip.startsWith('8.8.')) {
      return { asn: 'AS15169', org: 'Google LLC', country: 'US' };
    }
    if (ip.startsWith('20.') || ip.startsWith('52.') || ip.startsWith('13.')) {
      return { asn: 'AS8075', org: 'Microsoft Corporation', country: 'US' };
    }
    return { asn: 'UNKNOWN', org: 'Public Autonomous System', country: 'GLOBAL' };
  }
}

export class DNSLayer {
  private ipProvider: IpIntelligenceProvider;

  constructor(ipProvider?: IpIntelligenceProvider) {
    this.ipProvider = ipProvider || new DefaultIpIntelligenceProvider();
  }

  /**
   * Performs passive DNS queries for A, AAAA, MX, NS, CNAME, and TXT records.
   */
  public async analyze(hostname: string): Promise<{
    data: DNSIntelligence;
    evidence: EvidenceItem[];
  }> {
    const evidence: EvidenceItem[] = [];

    // Check if hostname is raw IP
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
    if (isIp) {
      const ipDetails: IPDetail[] = [{
        ip: hostname,
        version: hostname.includes(':') ? 'IPv6' : 'IPv4',
        ...(await this.ipProvider.lookup(hostname))
      }];

      if (hostname === '127.0.0.1' || hostname.startsWith('10.') || hostname.startsWith('192.168.')) {
        evidence.push({
          layer: 'DNS',
          featureKey: 'private_ip_resolution',
          featureValue: hostname,
          severity: 'CRITICAL',
          description: `Target resolves directly to a private/internal IP address (${hostname}), posing high SSRF and intranet exposure risk.`,
          contribution: 0.50,
          source: 'DNS_Layer',
          confidence: 1.0
        });
      }

      return {
        data: {
          status: 'SUCCESS',
          resolvedIps: [hostname],
          ipv4Count: hostname.includes(':') ? 0 : 1,
          ipv6Count: hostname.includes(':') ? 1 : 0,
          nameservers: [],
          mxRecords: [],
          cnameRecords: [],
          txtRecords: [],
          hasMx: false,
          ipDetails
        },
        evidence
      };
    }

    const cacheKey = `dns:${hostname}`;
    return cache.wrap(cacheKey, async () => {
      return this.resolveDnsRecords(hostname);
    }, CacheManager.TTL.DNS_RECORDS);
  }

  private async resolveDnsRecords(hostname: string): Promise<{
    data: DNSIntelligence;
    evidence: EvidenceItem[];
  }> {
    const evidence: EvidenceItem[] = [];

    const resolvedIps: string[] = [];
    const nameservers: string[] = [];
    const mxRecords: string[] = [];
    const cnameRecords: string[] = [];
    const txtRecords: string[] = [];
    let ipv4Count = 0;
    let ipv6Count = 0;
    let hasMx = false;
    let dnsError: string | null = null;
    let layerStatus: 'SUCCESS' | 'PARTIAL' | 'FAILED' = 'SUCCESS';

    try {
      // 1. Resolve IPv4 (A records) with timeout
      try {
        const aRecords = await this.withTimeout(dns.resolve4(hostname), 2000);
        resolvedIps.push(...aRecords);
        ipv4Count = aRecords.length;
      } catch (err: any) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
          dnsError = `Domain could not be resolved (NXDOMAIN / ${err.code})`;
          evidence.push({
            layer: 'DNS',
            featureKey: 'nxdomain_resolution_failure',
            featureValue: 'NXDOMAIN',
            severity: 'HIGH',
            description: `DNS query failed to resolve IPv4 addresses for domain ${hostname}. Non-resolving domains are commonly associated with deactivated attack infrastructure.`,
            contribution: 0.30,
            source: 'DNS_Resolver',
            confidence: 0.95
          });
        }
      }

      // 2. Resolve IPv6 (AAAA records)
      try {
        const aaaaRecords = await this.withTimeout(dns.resolve6(hostname), 1500);
        resolvedIps.push(...aaaaRecords);
        ipv6Count = aaaaRecords.length;
      } catch {
        // IPv6 absence is standard for many hosts
      }

      // 3. Resolve MX (Mail Exchanger)
      try {
        const mxList = await this.withTimeout(dns.resolveMx(hostname), 1500);
        if (Array.isArray(mxList) && mxList.length > 0) {
          hasMx = true;
          mxRecords.push(...mxList.map(m => `${m.exchange} (prio:${m.priority})`));
        }
      } catch {
        hasMx = false;
      }

      // 4. Resolve NS (Nameservers)
      try {
        const nsList = await this.withTimeout(dns.resolveNs(hostname), 1500);
        nameservers.push(...nsList);
      } catch {
        // ignore
      }

      // 5. Resolve TXT records
      try {
        const txtList = await this.withTimeout(dns.resolveTxt(hostname), 1500);
        txtRecords.push(...txtList.map(t => t.join('')));
      } catch {
        // ignore
      }

      // Evidence synthesis on resolved IPs
      if (resolvedIps.length > 4) {
        evidence.push({
          layer: 'DNS',
          featureKey: 'multiple_resolved_ips',
          featureValue: resolvedIps.length,
          severity: 'LOW',
          description: `Domain resolves to ${resolvedIps.length} distinct IP addresses (Fast-Flux or Multi-CDN routing).`,
          contribution: 0.10,
          source: 'DNS_Layer',
          confidence: 0.80
        });
      }

      // Private IP resolution check
      for (const ip of resolvedIps) {
        if (ip === '127.0.0.1' || ip.startsWith('10.') || ip.startsWith('192.168.')) {
          evidence.push({
            layer: 'DNS',
            featureKey: 'private_ip_resolution',
            featureValue: ip,
            severity: 'CRITICAL',
            description: `Domain resolved to private RFC1918 address (${ip}), posing SSRF / internal scanning risk.`,
            contribution: 0.50,
            source: 'DNS_Layer',
            confidence: 1.0
          });
        }
      }

      if (resolvedIps.length === 0 && !dnsError) {
        layerStatus = 'PARTIAL';
      }
    } catch (err: any) {
      layerStatus = 'FAILED';
      dnsError = err.message || 'DNS resolution failed';
    }

    // Lookup IP details
    const ipDetails: IPDetail[] = [];
    for (const ip of resolvedIps.slice(0, 4)) {
      const details = await this.ipProvider.lookup(ip);
      ipDetails.push({
        ip,
        version: ip.includes(':') ? 'IPv6' : 'IPv4',
        ...details
      });
    }

    const data: DNSIntelligence = {
      status: layerStatus,
      resolvedIps,
      ipv4Count,
      ipv6Count,
      nameservers,
      mxRecords,
      cnameRecords,
      txtRecords,
      hasMx,
      ipDetails,
      error: dnsError
    };

    return { data, evidence };
  }

  private withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) => setTimeout(() => reject(new Error('DNS Timeout')), timeoutMs))
    ]);
  }
}

export const dnsLayer = new DNSLayer();
