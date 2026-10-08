# ADR 0005: Threat Graph Engine & Campaign Infrastructure Clustering

## Status
**Accepted**

## Context
Phishing attackers rarely deploy isolated landing pages; they construct networks of shared domain registrars, nameservers, autonomous systems (ASNs), TLS certificate issuers, and IP subnets to execute wide-scale campaigns.

## Decision
We implemented a graph-relational threat modeling engine (`ThreatGraphEngine.ts`) and autonomous campaign clusterer (`CampaignClusteringEngine.ts`):
1. **Multi-Entity Graph Representation:**
   - Nodes: `DOMAIN`, `IP`, `ASN`, `CERTIFICATE`, `NAMESERVER`, `REGISTRAR`, `BRAND`, `CAMPAIGN`.
   - Edges: `RESOLVES_TO`, `HOSTED_ON`, `SECURED_BY`, `DELEGATED_TO`, `REGISTERED_BY`, `TARGETS_BRAND`, `ASSOCIATED_WITH`.
2. **Infrastructure Similarity Scoring:**
   - Evaluates shared structural elements: ASN overlap (weight: 0.25), Nameserver match (0.25), Shared TLS Issuer/Serial (0.20), Target Brand convergence (0.20), and Co-location subnets (0.10).
   - Groups related entities into distinct Threat Campaign rings when similarity exceeds 0.70.
3. **STIX 2.1 Threat Sharing:**
   - Automatically serializes graph entities and campaign indicators into OASIS STIX 2.1 standard JSON bundles for export to enterprise SIEM/SOAR and OpenCTI systems.

## Consequences
- **Positive:** Converts tactical indicator triage into strategic adversary campaign tracking.
- **Positive:** Enables 1-click enterprise-wide sinkholing across connected infrastructure nodes.
- **Trade-off:** Graph traversal requires memory indexing; bounded graph windowing prevents node explosion.
