# PhishNetra — Multi-Layer Threat Intelligence Specification

**Milestone:** Implementation 2 / Milestone 2  
**Status:** Completed & Operational  

---

## 1. Executive Overview

PhishNetra addresses modern phishing campaigns by replacing monolithic URL classifiers with an extensible, **Multi-Layer Zero-Trust Intelligence Architecture**. 

Modern phishing infrastructure frequently uses genuine HTTPS certificates, Cloudflare proxies, and disposable domains to evade traditional single-signal scanners. PhishNetra independently extracts intelligence across five distinct dimensions before synthesizing a final composite risk verdict:

```text
                               Target URL
                                    │
                                    ▼
                         URL Canonicalization
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
     ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
     │ Layer 1         │   │ Layer 2         │   │ Layer 3         │
     │ URL Intelligence│   │ Domain & RDAP   │   │ DNS & IP Intel  │
     │ (Lexical/Syntax)│   │ (Age, Registrar)│   │ (Records, Geo)  │
     └────────┬────────┘   └────────┬────────┘   └────────┬────────┘
              │                     │                     │
              └──────────────┬──────┴──────┬──────────────┘
                             ▼             ▼
                    ┌─────────────────┐   ┌─────────────────┐
                    │ Layer 4         │   │ Layer 5         │
                    │ TLS Intelligence│   │ Reputation Feed │
                    │ (Certs, Expiry) │   │ (URLhaus, VT..) │
                    └────────┬────────┘   └────────┬────────┘
                             │                     │
                             └──────────┬──────────┘
                                        │
                                        ▼
                             ┌─────────────────────┐
                             │ Layer 6: ML Baseline│
                             │ (Probability Vector)│
                             └──────────┬──────────┘
                                        │
                                        ▼
                             Multi-Layer Risk Engine
                               [Configurable Weights]
                                        │
                                        ▼
                             Layer-Grouped Evidence
                                        │
                                        ▼
                               Zero-Trust Verdict
```

---

## 2. Intelligence Layers Detailed

### Layer 1: URL Intelligence (`URLLayer`)
- **Structural Analysis:** Hostname length, path depth, query string parameters, fragment presence, subdomain count.
- **Lexical Signals:** Shannon character entropy, digit ratio, special character ratio, hyphen density.
- **Obfuscation Detection:** Hex-encoded structural delimiters (`%2F`, `%40`, `%3A`), embedded user credentials (`user@host`), non-standard HTTP ports (`8080`, `8443`, `8888`), Punycode IDN homoglyphs (`xn--...`), and URL shortening services (`bit.ly`, `tinyurl.com`, `t.co`).

### Layer 2: Domain Intelligence & RDAP (`DomainLayer`)
- **Public Suffix Parsing:** Extracts registrable root domain, second-level subdomains, and top-level domain (TLD).
- **Registration Data Access Protocol (RDAP):** Direct query to IANA/RDAP bootstrap gateways (`https://rdap.org/domain/{domain}`) with timeout and memory caching.
- **Domain Age Analysis:**
  - `< 30 days`: Newly registered domain (**HIGH** severity indicator).
  - `30–90 days`: Young domain (**MEDIUM** severity indicator).
  - `90–365 days`: Established domain.
  - `> 365 days`: Mature infrastructure (**INFO** indicator).
- **Registrar & Privacy:** Identifies whois proxy shields and registrar reputation.

### Layer 3: DNS & IP Intelligence (`DNSLayer`)
- **Passive DNS Querying:** Resolves A (IPv4), AAAA (IPv6), MX (Mail Exchanger), NS (Nameserver), CNAME, and TXT records using asynchronous DNS promises.
- **Infrastructure Profiling:** Evaluates resolved IP count (Fast-Flux / Multi-CDN detection) and MX record presence.
- **SSRF & Private Network Defense:** Flags RFC1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`) with **CRITICAL** severity to prevent intranet scanning.
- **IP Intelligence Provider Abstraction (`IpIntelligenceProvider`):** Resolves ASN, Organization, and Country metadata.

### Layer 4: TLS / Certificate Intelligence (`TLSLayer`)
- **Safe Socket Handshake:** Performs non-intrusive TLS handshake on port 443 with SNI (`servername: hostname`) without requesting HTTP response bodies.
- **Certificate Inspection:** Issuer authority, Subject Common Name (CN), Subject Alternative Names (SANs), TLS protocol version, validity window, and `daysUntilExpiry`.
- **Anomalies Flagged:** Expired certificates, self-signed/untrusted root CAs, and hostname mismatches.
- **Zero-Trust Rule:** Emphasizes that HTTPS validates transport encryption, NOT website benignity.

### Layer 5: Reputation Intelligence (`ReputationLayer`)
- **Extensible Provider Abstraction (`IReputationProvider`):**
  - `URLhausProvider`: Live community threat feed from Abuse.ch.
  - `PhishTankProvider`: Anti-phishing feed adapter.
  - `VirusTotalProvider`: Multi-engine scanner adapter.
- **Normalization Schema:** Maps vendor-specific formats to unified statuses (`CLEAN`, `MALICIOUS`, `SUSPICIOUS`, `NOT_CONFIGURED`, `FAILED`).
- **Resilience:** If provider API keys are unconfigured, status defaults to `NOT_CONFIGURED` without failing the overall analysis.

### Layer 6: Machine Learning Baseline (`MLClientService`)
- 18-signal deterministic feature extractor passed to `RandomForestClassifier` microservice.
- Outputs `phishing_probability` (0.0 to 1.0) and `confidence` rating.

---

## 3. Multi-Layer Risk Engine Scoring Model

The risk engine computes a composite weighted risk score (0 to 100):

$$\text{RiskScore} = \sum_{L \in \text{Layers}} w_L \cdot \text{Score}_L$$

### Default Layer Weights:
- **URL Intelligence:** 20%
- **Domain Intelligence:** 15%
- **DNS Intelligence:** 10%
- **TLS Intelligence:** 10%
- **Reputation Intelligence:** 25%
- **Machine Learning:** 20%

### Resilience & Weight Rebalancing
If an optional external provider is unconfigured or unavailable, its weight is dynamically redistributed across the active layers:

$$w_L' = \frac{w_L}{\sum_{k \in \text{Active}} w_k}$$

### Critical Overrides
- Active Blacklist Hit on Reputation Feeds $\implies \min(\text{RiskScore}, 85)$
- Private RFC1918 IP Resolution $\implies \min(\text{RiskScore}, 95)$

---

## 4. Evidence Schema

Every triggered indicator is encapsulated in an `EvidenceItem`:
```json
{
  "layer": "DOMAIN",
  "featureKey": "newly_registered_domain",
  "featureValue": "4 days",
  "severity": "HIGH",
  "description": "Domain was created 4 days ago (< 30 days). High correlation with disposable phishing campaigns.",
  "source": "RDAP",
  "confidence": 0.90,
  "contribution": 0.35
}
```
