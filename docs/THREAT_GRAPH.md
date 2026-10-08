# PhishNetra Threat Graph Engine, IOC Correlation & Autonomous Campaign Clustering

## 1. Overview & Architecture

The **PhishNetra Threat Graph Engine** elevates phishing threat mitigation from isolated domain inspection to an infrastructure-wide graph intelligence platform. By modeling relationships across DNS records, IP addresses, Autonomous Systems (ASNs), TLS certificates, Nameservers, Registrars, and targeted Brands, the engine correlates disparate phishing operations into unified **Threat Campaigns / Intrusion Sets**.

```
                           +-------------------------------------+
                           |      PhishNetra Threat Graph        |
                           +-------------------------------------+
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
             [DOMAIN Node]             [BRAND Node]             [CAMPAIGN Node]
          (login-paypal.xyz)             (PayPal)             (Campaign-ShadowNet)
                    │                         ▲                         ▲
          ┌─────────┴─────────┐               │                         │
          ▼                   ▼               │ IMPERSONATES            │ PART_OF_CAMPAIGN
     [IP Node]         [NAMESERVER Node] ─────┼─────────────────────────┘
   (185.220.101.5)     (ns1.bulletproof.cc)   │
          │                   │               │
          ▼                   ▼               │
     [ASN Node]        [CERTIFICATE Node] ────┘
    (AS200052)          (Let's Encrypt)
```

---

## 2. Graph Ontology & Relationship Schemas

### Entity Node Types (`GraphNodeType`)
- **`DOMAIN`**: Target websites, landing pages, and external form destinations.
- **`IP`**: Resolved IPv4 and IPv6 network hosts.
- **`ASN`**: Autonomous System Numbers and hosting organizations (e.g. `AS13335 Cloudflare`, `AS200052 Bulletproof Host`).
- **`CERTIFICATE`**: TLS/SSL public key certificates, issuers, validity windows, and serials.
- **`NAMESERVER`**: Authoritative DNS name servers managing target domains.
- **`REGISTRAR`**: Domain registration authorities (RDAP entities).
- **`BRAND`**: High-value corporate targets (e.g. PayPal, Microsoft, Apple, Binance, Chase).
- **`CAMPAIGN`**: Clustered threat rings sharing correlated infrastructure.

### Relationship Edge Types (`GraphEdgeType`)
- **`RESOLVES_TO`**: `DOMAIN → IP`
- **`HOSTED_ON`**: `IP → ASN`
- **`USES_CERTIFICATE`**: `DOMAIN → CERTIFICATE`
- **`MANAGED_BY_NS`**: `DOMAIN → NAMESERVER`
- **`REGISTERED_THROUGH`**: `DOMAIN → REGISTRAR`
- **`REDIRECTS_TO`**: `DOMAIN → DOMAIN` (via HTTP 3xx or Form Action)
- **`IMPERSONATES`**: `DOMAIN → BRAND`
- **`PART_OF_CAMPAIGN`**: `DOMAIN → CAMPAIGN`
- **`CO_LOCATED_WITH`**: `DOMAIN ↔ DOMAIN` (Sharing identical IP or NS)

---

## 3. Autonomous Campaign Clustering Engine

The clustering engine (`CampaignClusteringEngine.ts`) continuously aggregates malicious infrastructure using a weighted composite similarity matrix:

$$\text{Similarity}(D_1, D_2) = w_{\text{ASN}} \cdot \mathbb{I}(\text{ASN}) + w_{\text{NS}} \cdot \mathbb{I}(\text{NS}) + w_{\text{Brand}} \cdot \mathbb{I}(\text{Brand}) + w_{\text{IP}} \cdot \mathbb{I}(\text{IP}) + w_{\text{TLS}} \cdot \mathbb{I}(\text{TLS})$$

- **Shared ASN**: $0.35$ weight
- **Shared Nameserver**: $0.25$ weight
- **Shared Target Brand**: $0.25$ weight
- **Shared IP / Subnet (/24)**: $0.30$ ($0.15$ for subnet)
- **Shared TLS Certificate**: $0.15$ weight

Domains scoring $\ge 0.35$ composite similarity are automatically grouped into named Threat Campaigns with automated threat actor tagging, severity scoring, and full IOC catalogs.

---

## 4. OASIS STIX 2.1 Threat Sharing

PhishNetra exports all Threat Campaigns and sub-graphs into **OASIS STIX 2.1** compliant JSON bundles (`STIXExportService.ts`):
- **Identity Object**: `identity--...` representing the PhishNetra SOC Engine.
- **Campaign Object**: `campaign--...` detailing the attack objective and targeted sectors.
- **Identity Targets**: `identity--brand-...` describing impersonated organizations.
- **Cyber Observable Indicators**:
  - `[domain-name:value = 'attacker-phish.xyz']`
  - `[ipv4-addr:value = '185.220.101.5']`
- **Relationship Objects**: `targets`, `indicates`, and `attributed-to`.

---

## 5. REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/graph/overview` | Retrieves global high-level graph topology and stats |
| `GET` | `/api/graph/domain/:domain` | Retrieves k-hop sub-graph (1-hop, 2-hop, 3-hop) for target domain |
| `GET` | `/api/graph/nodes/:id/neighbors` | Traverses 1-hop immediate neighbors for canvas expansion |
| `GET` | `/api/graph/search?q=...` | Searches graph entities by label and type filter |
| `GET` | `/api/graph/export/stix` | Exports current graph or domain subgraph as STIX 2.1 bundle |
| `GET` | `/api/campaigns` | Lists detected Threat Campaigns with status/brand filters |
| `POST` | `/api/campaigns/cluster` | Triggers autonomous on-demand campaign re-clustering |
| `GET` | `/api/campaigns/:id` | Detailed campaign profile with connected IOC list |
| `GET` | `/api/campaigns/:id/stix` | Downloads STIX 2.1 JSON bundle for a specific campaign |

---

## 6. Interactive SOC Graph Explorer (`/graph` & `/campaigns`)

- **Force-Directed Physics Simulation**: Smooth Coulomb-repulsion and Hooke's-spring attraction for clear visual clustering.
- **Interactive Viewport**: Drag-and-drop nodes, dynamic pan and zoom controls, reset view.
- **Entity Inspector Drawer**: Real-time metadata view, risk severity bar, connected IOC list, and instant 1-hop neighbor expansion.
- **Campaign Management Console**: Filter by status, view IOC counts, inspect targeted brands, and download STIX 2.1 bundles with one click.
