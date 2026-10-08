/**
 * PhishNetra — Autonomous Threat Campaign Clustering Engine
 * 
 * Performs graph-based infrastructure correlation and clustering across
 * malicious domains sharing ASNs, Nameservers, TLS fingerprints, and Brand targets.
 */

import { prisma } from '../../db/prisma';
import { ThreatCampaign, CampaignClusterResult } from '@phishnetra/shared';
import { ThreatGraphEngine } from './ThreatGraphEngine';
import { STIXExportService } from './STIXExportService';
import crypto from 'crypto';

interface DomainInfrastructureProfile {
  domainId: string;
  domainName: string;
  riskScore: number;
  riskLevel: string;
  ips: string[];
  asns: string[];
  nameservers: string[];
  brands: string[];
  certificates: string[];
  registrars: string[];
  firstSeen: Date;
  lastSeen: Date;
}

export class CampaignClusteringEngine {
  /**
   * Evaluates graph relationships and clusters malicious infrastructure into named Threat Campaigns
   */
  public static async runClustering(): Promise<CampaignClusterResult> {
    // 1. Fetch high-risk domain nodes
    const highRiskDomains = await prisma.graphNode.findMany({
      where: {
        type: 'DOMAIN',
        OR: [
          { riskScore: { gte: 45 } },
          { riskLevel: { in: ['HIGH', 'CRITICAL'] } }
        ]
      }
    });

    if (highRiskDomains.length === 0) {
      const existingCampaigns = await this.listCampaigns();
      return {
        totalCampaigns: existingCampaigns.length,
        newCampaignsCreated: 0,
        domainsClustered: 0,
        campaigns: existingCampaigns
      };
    }

    // 2. Build infrastructure profiles for each domain
    const profiles: DomainInfrastructureProfile[] = [];

    for (const d of highRiskDomains) {
      const edges = await prisma.graphEdge.findMany({
        where: { sourceId: d.id },
        include: { targetNode: true }
      });

      const profile: DomainInfrastructureProfile = {
        domainId: d.id,
        domainName: d.label,
        riskScore: d.riskScore || 50,
        riskLevel: d.riskLevel || 'HIGH',
        ips: [],
        asns: [],
        nameservers: [],
        brands: [],
        certificates: [],
        registrars: [],
        firstSeen: d.firstSeen,
        lastSeen: d.lastSeen
      };

      for (const e of edges) {
        if (e.targetNode.type === 'IP') profile.ips.push(e.targetNode.label);
        if (e.targetNode.type === 'ASN') profile.asns.push(e.targetNode.label);
        if (e.targetNode.type === 'NAMESERVER') profile.nameservers.push(e.targetNode.label);
        if (e.targetNode.type === 'BRAND') profile.brands.push(e.targetNode.label);
        if (e.targetNode.type === 'CERTIFICATE') profile.certificates.push(e.targetNode.label);
        if (e.targetNode.type === 'REGISTRAR') profile.registrars.push(e.targetNode.label);
      }

      profiles.push(profile);
    }

    // 3. Pairwise Infrastructure Similarity & Connected Component Grouping
    const clusters: DomainInfrastructureProfile[][] = [];
    const visited = new Set<string>();

    for (let i = 0; i < profiles.length; i++) {
      const p1 = profiles[i];
      if (visited.has(p1.domainId)) continue;

      const currentCluster: DomainInfrastructureProfile[] = [p1];
      visited.add(p1.domainId);

      for (let j = i + 1; j < profiles.length; j++) {
        const p2 = profiles[j];
        if (visited.has(p2.domainId)) continue;

        const similarity = this.calculateInfrastructureSimilarity(p1, p2);
        if (similarity >= 0.35) {
          currentCluster.push(p2);
          visited.add(p2.domainId);
        }
      }

      clusters.push(currentCluster);
    }

    let newCampaignsCount = 0;
    const generatedCampaigns: ThreatCampaign[] = [];

    // 4. Upsert ThreatCampaign entities
    for (const cluster of clusters) {
      const allDomains = Array.from(new Set(cluster.map((c) => c.domainName)));
      const allIps = Array.from(new Set(cluster.flatMap((c) => c.ips)));
      const allAsns = Array.from(new Set(cluster.flatMap((c) => c.asns)));
      const allNs = Array.from(new Set(cluster.flatMap((c) => c.nameservers)));
      const allBrands = Array.from(new Set(cluster.flatMap((c) => c.brands)));

      const primaryBrand = allBrands[0] || 'Multi-Target';
      const primaryAsn = allAsns[0] || 'ShadowNet';
      const avgScore = cluster.reduce((sum, c) => sum + c.riskScore, 0) / cluster.length;

      const campaignName = cluster.length > 1
        ? `Campaign [${primaryBrand}] — ${primaryAsn} Cluster`
        : `Threat Ring [${primaryBrand}] — ${cluster[0].domainName}`;

      const earliestDate = new Date(Math.min(...cluster.map((c) => c.firstSeen.getTime())));
      const latestDate = new Date(Math.max(...cluster.map((c) => c.lastSeen.getTime())));

      const description = `Automated cluster aggregating ${allDomains.length} phishing domain(s) targeting ${allBrands.join(', ') || 'credentials'} hosted on ${allAsns.join(', ') || 'unspecified infrastructure'}.`;

      const campaignId = `campaign-${crypto.randomUUID().substring(0, 8)}`;

      const campaignObj: ThreatCampaign = {
        id: campaignId,
        name: campaignName,
        threatActor: allAsns.length > 0 ? `Unattributed (${allAsns[0]})` : 'Unknown Actor',
        targetedBrands: allBrands,
        riskLevel: avgScore >= 75 ? 'CRITICAL' : 'HIGH',
        severityScore: Math.round(avgScore),
        status: 'ACTIVE',
        domainCount: allDomains.length,
        ipCount: allIps.length,
        iocs: {
          domains: allDomains,
          ips: allIps,
          asns: allAsns,
          nameservers: allNs
        },
        description,
        firstSeen: earliestDate.toISOString(),
        lastSeen: latestDate.toISOString()
      };

      // Generate STIX bundle
      campaignObj.stixBundle = STIXExportService.generateCampaignSTIXBundle(campaignObj);

      // Save to Database
      await prisma.threatCampaign.create({
        data: {
          id: campaignObj.id,
          name: campaignObj.name,
          threatActor: campaignObj.threatActor,
          targetedBrands: JSON.stringify(campaignObj.targetedBrands),
          riskLevel: campaignObj.riskLevel,
          severityScore: campaignObj.severityScore,
          status: campaignObj.status,
          domainCount: campaignObj.domainCount,
          ipCount: campaignObj.ipCount,
          iocsJson: JSON.stringify(campaignObj.iocs),
          description: campaignObj.description,
          firstSeen: earliestDate,
          lastSeen: latestDate
        }
      });

      newCampaignsCount++;
      generatedCampaigns.push(campaignObj);

      // 5. Ingest Campaign Node and link to Domains in Threat Graph
      const campaignNodeId = `campaign:${campaignObj.id}`;
      await ThreatGraphEngine.upsertNode(
        campaignNodeId,
        campaignObj.name,
        'CAMPAIGN',
        {
          targetedBrands: campaignObj.targetedBrands,
          domainCount: campaignObj.domainCount,
          severityScore: campaignObj.severityScore
        },
        campaignObj.severityScore,
        campaignObj.riskLevel
      );

      for (const p of cluster) {
        await ThreatGraphEngine.upsertEdge(p.domainId, campaignNodeId, 'PART_OF_CAMPAIGN', 1.0);
      }
    }

    const allCampaigns = await this.listCampaigns();

    return {
      totalCampaigns: allCampaigns.length,
      newCampaignsCreated: newCampaignsCount,
      domainsClustered: highRiskDomains.length,
      campaigns: allCampaigns
    };
  }

  /**
   * Calculates similarity coefficient between two domain infrastructure profiles (0.0 to 1.0)
   */
  private static calculateInfrastructureSimilarity(p1: DomainInfrastructureProfile, p2: DomainInfrastructureProfile): number {
    let score = 0;

    // 1. Shared ASN
    const sharedAsns = p1.asns.filter((a) => p2.asns.includes(a));
    if (sharedAsns.length > 0) score += 0.35;

    // 2. Shared Nameservers
    const sharedNs = p1.nameservers.filter((n) => p2.nameservers.includes(n));
    if (sharedNs.length > 0) score += 0.25;

    // 3. Shared Targeted Brand
    const sharedBrands = p1.brands.filter((b) => p2.brands.includes(b));
    if (sharedBrands.length > 0) score += 0.25;

    // 4. Shared IP addresses or Subnets
    const sharedIps = p1.ips.filter((ip) => p2.ips.includes(ip));
    if (sharedIps.length > 0) {
      score += 0.30;
    } else {
      // Check /24 subnet match
      const p1Subnets = p1.ips.map((ip) => ip.split('.').slice(0, 3).join('.'));
      const p2Subnets = p2.ips.map((ip) => ip.split('.').slice(0, 3).join('.'));
      if (p1Subnets.some((s) => p2Subnets.includes(s))) {
        score += 0.15;
      }
    }

    // 5. Shared TLS Certificate / Issuer
    const sharedCerts = p1.certificates.filter((c) => p2.certificates.includes(c));
    if (sharedCerts.length > 0) score += 0.15;

    return Math.min(1.0, score);
  }

  /**
   * Lists all campaigns with optional brand or status filters
   */
  public static async listCampaigns(filters?: { status?: string; brand?: string; limit?: number }): Promise<ThreatCampaign[]> {
    const where: any = {};
    if (filters?.status && filters.status !== 'ALL') {
      where.status = filters.status;
    }

    const dbCampaigns = await prisma.threatCampaign.findMany({
      where,
      orderBy: { lastSeen: 'desc' },
      take: filters?.limit || 50
    });

    return dbCampaigns.map((c: any) => {
      let targetedBrands: string[] = [];
      try {
        targetedBrands = JSON.parse(c.targetedBrands);
      } catch {}

      let iocs = { domains: [], ips: [], asns: [] };
      try {
        iocs = JSON.parse(c.iocsJson);
      } catch {}

      const campaign: ThreatCampaign = {
        id: c.id,
        name: c.name,
        threatActor: c.threatActor,
        targetedBrands,
        riskLevel: c.riskLevel as any,
        severityScore: c.severityScore,
        status: c.status as any,
        domainCount: c.domainCount,
        ipCount: c.ipCount,
        iocs,
        description: c.description,
        firstSeen: c.firstSeen.toISOString(),
        lastSeen: c.lastSeen.toISOString()
      };

      campaign.stixBundle = STIXExportService.generateCampaignSTIXBundle(campaign);
      return campaign;
    });
  }

  /**
   * Retrieves single campaign by ID
   */
  public static async getCampaignById(id: string): Promise<ThreatCampaign | null> {
    const c = await prisma.threatCampaign.findUnique({ where: { id } });
    if (!c) return null;

    let targetedBrands: string[] = [];
    try {
      targetedBrands = JSON.parse(c.targetedBrands);
    } catch {}

    let iocs = { domains: [], ips: [], asns: [] };
    try {
      iocs = JSON.parse(c.iocsJson);
    } catch {}

    const campaign: ThreatCampaign = {
      id: c.id,
      name: c.name,
      threatActor: c.threatActor,
      targetedBrands,
      riskLevel: c.riskLevel as any,
      severityScore: c.severityScore,
      status: c.status as any,
      domainCount: c.domainCount,
      ipCount: c.ipCount,
      iocs,
      description: c.description,
      firstSeen: c.firstSeen.toISOString(),
      lastSeen: c.lastSeen.toISOString()
    };

    campaign.stixBundle = STIXExportService.generateCampaignSTIXBundle(campaign);
    return campaign;
  }
}
