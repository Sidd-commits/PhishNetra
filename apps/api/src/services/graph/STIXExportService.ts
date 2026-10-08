/**
 * PhishNetra — STIX 2.1 Export Service
 * 
 * Generates OASIS STIX 2.1 compliant Threat Intelligence JSON bundles
 * for seamless integration with enterprise SIEMs, SOAR platforms, MISP, and OpenCTI.
 */

import { ThreatCampaign, GraphData } from '@phishnetra/shared';
import crypto from 'crypto';

export class STIXExportService {
  /**
   * Generates a STIX 2.1 Bundle from a ThreatCampaign entity
   */
  public static generateCampaignSTIXBundle(campaign: ThreatCampaign): Record<string, any> {
    const bundleId = `bundle--${crypto.randomUUID()}`;
    const timestamp = new Date().toISOString();

    const objects: Record<string, any>[] = [];

    // 1. Identity (PhishNetra Engine)
    const identityId = 'identity--4a78c91d-9e12-4c27-a129-phishnetra-core';
    objects.push({
      type: 'identity',
      spec_version: '2.1',
      id: identityId,
      created: timestamp,
      modified: timestamp,
      name: 'PhishNetra Threat Intelligence Engine',
      identity_class: 'system',
      description: 'Autonomous multi-layer zero-trust phishing detection and IOC correlation platform'
    });

    // 2. STIX Campaign Object
    const campaignId = `campaign--${campaign.id.includes('--') ? campaign.id.split('--')[1] : campaign.id}`;
    objects.push({
      type: 'campaign',
      spec_version: '2.1',
      id: campaignId,
      created: campaign.firstSeen || timestamp,
      modified: campaign.lastSeen || timestamp,
      name: campaign.name,
      description: campaign.description,
      first_seen: campaign.firstSeen || timestamp,
      last_seen: campaign.lastSeen || timestamp,
      objective: `Credential harvesting and brand impersonation targeting ${campaign.targetedBrands.join(', ') || 'unspecified institutions'}`
    });

    // 3. STIX Target Identities (Impersonated Brands)
    for (const brand of campaign.targetedBrands) {
      const brandIdentityId = `identity--brand-${encodeURIComponent(brand.toLowerCase())}-${crypto.randomUUID()}`;
      objects.push({
        type: 'identity',
        spec_version: '2.1',
        id: brandIdentityId,
        created: timestamp,
        modified: timestamp,
        name: brand,
        identity_class: 'organization',
        sectors: ['financial-services', 'technology', 'commercial']
      });

      // Relationship: Campaign targets Brand
      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: `relationship--${crypto.randomUUID()}`,
        created: timestamp,
        modified: timestamp,
        relationship_type: 'targets',
        source_ref: campaignId,
        target_ref: brandIdentityId
      });
    }

    // 4. STIX Indicator & Observable Objects for Domains
    for (const domain of campaign.iocs.domains || []) {
      const indicatorId = `indicator--domain-${crypto.randomUUID()}`;
      objects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: indicatorId,
        created: timestamp,
        modified: timestamp,
        name: `Phishing Domain IOC: ${domain}`,
        description: `Malicious domain associated with ${campaign.name}`,
        indicator_types: ['malicious-activity'],
        pattern_type: 'stix',
        pattern: `[domain-name:value = '${domain}']`,
        valid_from: campaign.firstSeen || timestamp
      });

      // Relationship: Indicator indicates Campaign
      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: `relationship--${crypto.randomUUID()}`,
        created: timestamp,
        modified: timestamp,
        relationship_type: 'indicates',
        source_ref: indicatorId,
        target_ref: campaignId
      });
    }

    // 5. STIX Indicator & Observable Objects for IPs
    for (const ip of campaign.iocs.ips || []) {
      const ipIndicatorId = `indicator--ip-${crypto.randomUUID()}`;
      objects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: ipIndicatorId,
        created: timestamp,
        modified: timestamp,
        name: `Phishing Hosting IP IOC: ${ip}`,
        description: `Hosting infrastructure for ${campaign.name}`,
        indicator_types: ['malicious-activity'],
        pattern_type: 'stix',
        pattern: `[ipv4-addr:value = '${ip}']`,
        valid_from: campaign.firstSeen || timestamp
      });

      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: `relationship--${crypto.randomUUID()}`,
        created: timestamp,
        modified: timestamp,
        relationship_type: 'indicates',
        source_ref: ipIndicatorId,
        target_ref: campaignId
      });
    }

    return {
      type: 'bundle',
      id: bundleId,
      spec_version: '2.1',
      objects
    };
  }

  /**
   * Generates a STIX 2.1 Bundle from any generic GraphData subgraph
   */
  public static generateGraphSTIXBundle(graph: GraphData, _title = 'PhishNetra Infrastructure Graph Export'): Record<string, any> {
    const bundleId = `bundle--${crypto.randomUUID()}`;
    const timestamp = new Date().toISOString();
    const objects: Record<string, any>[] = [];

    for (const node of graph.nodes) {
      if (node.type === 'DOMAIN') {
        objects.push({
          type: 'indicator',
          spec_version: '2.1',
          id: `indicator--${crypto.randomUUID()}`,
          created: node.firstSeen || timestamp,
          modified: node.lastSeen || timestamp,
          name: `Domain: ${node.label}`,
          pattern_type: 'stix',
          pattern: `[domain-name:value = '${node.label}']`,
          confidence: node.riskScore || 80,
          valid_from: node.firstSeen || timestamp
        });
      } else if (node.type === 'IP') {
        objects.push({
          type: 'indicator',
          spec_version: '2.1',
          id: `indicator--${crypto.randomUUID()}`,
          created: node.firstSeen || timestamp,
          modified: node.lastSeen || timestamp,
          name: `IP: ${node.label}`,
          pattern_type: 'stix',
          pattern: `[ipv4-addr:value = '${node.label}']`,
          valid_from: node.firstSeen || timestamp
        });
      }
    }

    return {
      type: 'bundle',
      id: bundleId,
      spec_version: '2.1',
      objects
    };
  }
}
