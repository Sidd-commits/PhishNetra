/**
 * PhishNetra — Threat Graph Engine
 * 
 * Orchestrates graph entity extraction, infrastructure correlation,
 * co-location linking, and sub-graph neighborhood traversals.
 */

import { prisma } from '../../db/prisma';
import { AnalysisResponse, GraphData, GraphNode, GraphEdge, GraphNodeType, GraphEdgeType } from '@phishnetra/shared';
import crypto from 'crypto';

export class ThreatGraphEngine {
  /**
   * Upserts a graph node into the database
   */
  public static async upsertNode(
    id: string,
    label: string,
    type: GraphNodeType,
    properties: Record<string, any> = {},
    riskScore?: number,
    riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  ): Promise<any> {
    const now = new Date();

    return prisma.graphNode.upsert({
      where: { id },
      update: {
        label,
        riskScore: riskScore !== undefined ? riskScore : undefined,
        riskLevel: riskLevel !== undefined ? riskLevel : undefined,
        propertiesJson: JSON.stringify(properties),
        lastSeen: now
      },
      create: {
        id,
        label,
        type,
        riskScore,
        riskLevel,
        propertiesJson: JSON.stringify(properties),
        firstSeen: now,
        lastSeen: now
      }
    });
  }

  /**
   * Upserts a graph edge connecting two nodes
   */
  public static async upsertEdge(
    sourceId: string,
    targetId: string,
    type: GraphEdgeType,
    weight = 1.0,
    properties: Record<string, any> = {}
  ): Promise<any> {
    const now = new Date();

    const existing = await prisma.graphEdge.findFirst({
      where: { sourceId, targetId, type }
    });

    if (existing) {
      return prisma.graphEdge.update({
        where: { id: existing.id },
        data: {
          weight,
          propertiesJson: JSON.stringify(properties),
          lastSeen: now
        }
      });
    }

    return prisma.graphEdge.create({
      data: {
        id: crypto.randomUUID(),
        sourceId,
        targetId,
        type,
        weight,
        propertiesJson: JSON.stringify(properties),
        firstSeen: now,
        lastSeen: now
      }
    });
  }

  /**
   * Ingests a complete multi-layer analysis response into the Threat Graph
   */
  public static async ingestAnalysis(analysis: AnalysisResponse): Promise<void> {
    try {
      const parsedUrl = new URL(analysis.url);
      const domain = parsedUrl.hostname.toLowerCase();
      const domainNodeId = `domain:${domain}`;

      // 1. Ingest Main Domain Node
      await this.upsertNode(
        domainNodeId,
        domain,
        'DOMAIN',
        {
          url: analysis.url,
          verdict: analysis.verdict,
          confidence: analysis.confidence,
          mlProbability: analysis.mlProbability
        },
        analysis.riskScore,
        analysis.riskLevel
      );

      const layers = analysis.layers;

      // 2. Ingest DNS & IP Infrastructure
      if (layers?.dns) {
        const resolvedIps = layers.dns.resolvedIps || [];
        const ipDetails = layers.dns.ipDetails || [];

        for (const ip of resolvedIps) {
          const ipNodeId = `ip:${ip}`;
          const detail = ipDetails.find((d: any) => d.ip === ip);

          await this.upsertNode(
            ipNodeId,
            ip,
            'IP',
            {
              version: detail?.version || 'IPv4',
              country: detail?.country,
              org: detail?.org,
              asn: detail?.asn
            },
            analysis.riskLevel === 'CRITICAL' ? 85 : 20,
            analysis.riskLevel === 'CRITICAL' ? 'HIGH' : 'LOW'
          );

          // Edge: Domain -> Resolves To -> IP
          await this.upsertEdge(domainNodeId, ipNodeId, 'RESOLVES_TO', 1.0);

          // 3. Ingest ASN Node
          if (detail?.asn) {
            const asnClean = detail.asn.toUpperCase().trim();
            const asnNodeId = `asn:${asnClean}`;

            await this.upsertNode(
              asnNodeId,
              asnClean,
              'ASN',
              { org: detail.org, country: detail.country },
              analysis.riskLevel === 'CRITICAL' ? 70 : 10
            );

            // Edge: IP -> Hosted On -> ASN
            await this.upsertEdge(ipNodeId, asnNodeId, 'HOSTED_ON', 1.0);
          }
        }

        // 4. Ingest Nameservers
        for (const ns of layers.dns.nameservers || []) {
          const nsClean = ns.toLowerCase().trim().replace(/\.$/, '');
          if (!nsClean) continue;
          const nsNodeId = `ns:${nsClean}`;

          await this.upsertNode(nsNodeId, nsClean, 'NAMESERVER', {});
          await this.upsertEdge(domainNodeId, nsNodeId, 'MANAGED_BY_NS', 1.0);
        }
      }

      // 5. Ingest Registrar from RDAP
      if (layers?.domain?.registrar) {
        const registrarClean = layers.domain.registrar.trim();
        if (registrarClean) {
          const registrarNodeId = `registrar:${registrarClean.toLowerCase()}`;
          await this.upsertNode(registrarNodeId, registrarClean, 'REGISTRAR', {
            domainAgeDays: layers.domain.domainAgeDays,
            creationDate: layers.domain.creationDate
          });
          await this.upsertEdge(domainNodeId, registrarNodeId, 'REGISTERED_THROUGH', 1.0);
        }
      }

      // 6. Ingest TLS Certificate
      if (layers?.tls && layers.tls.hasTls && layers.tls.issuer) {
        const issuerClean = layers.tls.issuer.trim();
        const certFingerprint = `${issuerClean}_${layers.tls.validTo || 'unknown'}`;
        const certNodeId = `cert:${certFingerprint}`;

        await this.upsertNode(certNodeId, `SSL: ${issuerClean}`, 'CERTIFICATE', {
          issuer: layers.tls.issuer,
          subject: layers.tls.subject,
          validFrom: layers.tls.validFrom,
          validTo: layers.tls.validTo,
          daysUntilExpiry: layers.tls.daysUntilExpiry
        });
        await this.upsertEdge(domainNodeId, certNodeId, 'USES_CERTIFICATE', 1.0);
      }

      // 7. Ingest Impersonated Brands
      if (analysis.pageAnalysis?.brandFindings) {
        for (const brandFinding of analysis.pageAnalysis.brandFindings) {
          if (brandFinding.isMismatch && brandFinding.claimedBrand) {
            const brandClean = brandFinding.claimedBrand.trim();
            const brandNodeId = `brand:${brandClean.toLowerCase()}`;

            await this.upsertNode(brandNodeId, brandClean, 'BRAND', {
              authenticDomain: brandFinding.authenticDomain,
              confidence: brandFinding.confidence
            }, 0, 'LOW');

            await this.upsertEdge(domainNodeId, brandNodeId, 'IMPERSONATES', brandFinding.confidence);
          }
        }
      }

      // 8. Ingest External Form Actions
      if (analysis.pageAnalysis?.forms) {
        for (const form of analysis.pageAnalysis.forms) {
          if (form.isCrossOrigin && form.actionResolved) {
            try {
              const formHost = new URL(form.actionResolved).hostname.toLowerCase();
              if (formHost && formHost !== domain) {
                const extDomainNodeId = `domain:${formHost}`;
                await this.upsertNode(extDomainNodeId, formHost, 'DOMAIN', {
                  isFormDestination: true,
                  hasPasswordField: form.hasPasswordField
                }, form.hasPasswordField ? 85 : 40);

                await this.upsertEdge(domainNodeId, extDomainNodeId, 'REDIRECTS_TO', 1.0, {
                  hasPasswordField: form.hasPasswordField
                });
              }
            } catch {
              // Ignore invalid form action URLs
            }
          }
        }
      }

      // 9. Auto-Link Co-Located Malicious Domains
      await this.autoLinkCoLocation(domainNodeId);
    } catch (err) {
      console.error('[ThreatGraphEngine] Ingest error:', err);
    }
  }

  /**
   * Finds co-located domains sharing the same IPs or Nameservers and creates CO_LOCATED_WITH edges
   */
  private static async autoLinkCoLocation(domainNodeId: string): Promise<void> {
    try {
      // Find all IPs and NSs connected to this domain
      const outgoing = await prisma.graphEdge.findMany({
        where: {
          sourceId: domainNodeId,
          type: { in: ['RESOLVES_TO', 'MANAGED_BY_NS'] }
        }
      });

      const targetIds = outgoing.map((e: any) => e.targetId);
      if (targetIds.length === 0) return;

      // Find other domains that point to these exact same target nodes
      const coLocatedEdges = await prisma.graphEdge.findMany({
        where: {
          targetId: { in: targetIds },
          sourceId: { not: domainNodeId }
        }
      });

      for (const edge of coLocatedEdges) {
        if (edge.sourceId.startsWith('domain:')) {
          await this.upsertEdge(domainNodeId, edge.sourceId, 'CO_LOCATED_WITH', 0.8, {
            sharedEntity: edge.targetId
          });
        }
      }
    } catch (err) {
      // Non-critical background correlation
    }
  }

  /**
   * Retrieves a k-hop sub-graph centered around a specific domain
   */
  public static async getDomainSubGraph(domain: string, depth = 2, maxNodes = 100): Promise<GraphData> {
    const cleanDomain = domain.toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const rootNodeId = `domain:${cleanDomain}`;

    const visitedNodeIds = new Set<string>([rootNodeId]);
    let currentLevelIds = [rootNodeId];

    const collectedNodesMap = new Map<string, GraphNode>();
    const collectedEdgesMap = new Map<string, GraphEdge>();

    // Initial root node fetch
    const rootNode = await prisma.graphNode.findUnique({ where: { id: rootNodeId } });
    if (rootNode) {
      collectedNodesMap.set(rootNode.id, this.mapDbNodeToGraphNode(rootNode));
    }

    for (let d = 0; d < depth; d++) {
      if (currentLevelIds.length === 0 || collectedNodesMap.size >= maxNodes) break;

      // Fetch edges where source OR target is in currentLevelIds
      const edges = await prisma.graphEdge.findMany({
        where: {
          OR: [
            { sourceId: { in: currentLevelIds } },
            { targetId: { in: currentLevelIds } }
          ]
        },
        include: {
          sourceNode: true,
          targetNode: true
        },
        take: Math.max(maxNodes * 4, 300)
      });

      const nextLevelIds: string[] = [];

      for (const edge of edges) {
        collectedEdgesMap.set(edge.id, this.mapDbEdgeToGraphEdge(edge));

        if (!collectedNodesMap.has(edge.sourceNode.id)) {
          collectedNodesMap.set(edge.sourceNode.id, this.mapDbNodeToGraphNode(edge.sourceNode));
        }
        if (!collectedNodesMap.has(edge.targetNode.id)) {
          collectedNodesMap.set(edge.targetNode.id, this.mapDbNodeToGraphNode(edge.targetNode));
        }

        if (!visitedNodeIds.has(edge.sourceNode.id)) {
          visitedNodeIds.add(edge.sourceNode.id);
          nextLevelIds.push(edge.sourceNode.id);
        }
        if (!visitedNodeIds.has(edge.targetNode.id)) {
          visitedNodeIds.add(edge.targetNode.id);
          nextLevelIds.push(edge.targetNode.id);
        }
      }

      currentLevelIds = nextLevelIds;
    }

    const nodes = Array.from(collectedNodesMap.values());
    const edges = Array.from(collectedEdgesMap.values());

    return {
      nodes,
      edges,
      stats: {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        domainCount: nodes.filter((n: GraphNode) => n.type === 'DOMAIN').length,
        ipCount: nodes.filter((n: GraphNode) => n.type === 'IP').length,
        campaignCount: nodes.filter((n: GraphNode) => n.type === 'CAMPAIGN').length
      }
    };
  }

  /**
   * Retrieves 1-hop immediate neighbors for a specific node ID
   */
  public static async getNodeNeighbors(nodeId: string, limit = 40): Promise<GraphData> {
    const centerNode = await prisma.graphNode.findUnique({ where: { id: nodeId } });
    if (!centerNode) {
      return { nodes: [], edges: [] };
    }

    const edges = await prisma.graphEdge.findMany({
      where: {
        OR: [
          { sourceId: nodeId },
          { targetId: nodeId }
        ]
      },
      include: {
        sourceNode: true,
        targetNode: true
      },
      take: limit
    });

    const nodesMap = new Map<string, GraphNode>();
    nodesMap.set(centerNode.id, this.mapDbNodeToGraphNode(centerNode));

    const edgeList: GraphEdge[] = [];
    for (const e of edges) {
      edgeList.push(this.mapDbEdgeToGraphEdge(e));
      nodesMap.set(e.sourceNode.id, this.mapDbNodeToGraphNode(e.sourceNode));
      nodesMap.set(e.targetNode.id, this.mapDbNodeToGraphNode(e.targetNode));
    }

    return {
      nodes: Array.from(nodesMap.values()),
      edges: edgeList
    };
  }

  /**
   * Generates high-level Threat Graph Overview statistics and top connected hubs
   */
  public static async getGraphOverview(limit = 100): Promise<GraphData & { topHubs: any[] }> {
    const [totalNodes, totalEdges, nodes, edges] = await Promise.all([
      prisma.graphNode.count(),
      prisma.graphEdge.count(),
      prisma.graphNode.findMany({
        orderBy: { lastSeen: 'desc' },
        take: limit
      }),
      prisma.graphEdge.findMany({
        orderBy: { lastSeen: 'desc' },
        take: limit * 2
      })
    ]);

    const mappedNodes = nodes.map(this.mapDbNodeToGraphNode);
    const mappedEdges = edges.map(this.mapDbEdgeToGraphEdge);

    return {
      nodes: mappedNodes,
      edges: mappedEdges,
      stats: {
        totalNodes,
        totalEdges,
        domainCount: nodes.filter((n: any) => n.type === 'DOMAIN').length,
        ipCount: nodes.filter((n: any) => n.type === 'IP').length,
        campaignCount: nodes.filter((n: any) => n.type === 'CAMPAIGN').length
      },
      topHubs: []
    };
  }

  /**
   * Searches nodes by label keyword and optional type filter
   */
  public static async searchNodes(query: string, typeFilter?: string, limit = 25): Promise<GraphNode[]> {
    const whereClause: any = {
      label: { contains: query }
    };
    if (typeFilter && typeFilter !== 'ALL') {
      whereClause.type = typeFilter;
    }

    const nodes = await prisma.graphNode.findMany({
      where: whereClause,
      take: limit,
      orderBy: { riskScore: 'desc' }
    });

    return nodes.map(this.mapDbNodeToGraphNode);
  }

  private static mapDbNodeToGraphNode(dbNode: any): GraphNode {
    let properties = {};
    if (dbNode.propertiesJson) {
      try {
        properties = JSON.parse(dbNode.propertiesJson);
      } catch {}
    }

    return {
      id: dbNode.id,
      label: dbNode.label,
      type: dbNode.type as GraphNodeType,
      riskScore: dbNode.riskScore ?? undefined,
      riskLevel: dbNode.riskLevel ?? undefined,
      properties,
      firstSeen: dbNode.firstSeen.toISOString(),
      lastSeen: dbNode.lastSeen.toISOString()
    };
  }

  private static mapDbEdgeToGraphEdge(dbEdge: any): GraphEdge {
    let properties = {};
    if (dbEdge.propertiesJson) {
      try {
        properties = JSON.parse(dbEdge.propertiesJson);
      } catch {}
    }

    return {
      id: dbEdge.id,
      source: dbEdge.sourceId,
      target: dbEdge.targetId,
      type: dbEdge.type as GraphEdgeType,
      weight: dbEdge.weight || 1.0,
      properties,
      firstSeen: dbEdge.firstSeen.toISOString(),
      lastSeen: dbEdge.lastSeen.toISOString()
    };
  }
}
