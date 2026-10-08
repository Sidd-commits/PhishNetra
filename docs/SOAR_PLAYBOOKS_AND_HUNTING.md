# PhishNetra SOAR Playbooks, Threat Hunting Lab & Threat Intel Connectors

## 1. Overview
Milestone 13 introduces enterprise-grade **Autonomous SOAR Playbook Orchestration**, a proactive **Multi-Vector Threat Hunting Lab with Forensic Replay Sandbox**, and multi-source **Threat Intelligence Connectors** (TAXII 2.1, MISP, AlienVault OTX, AbuseIPDB).

---

## 2. Architecture & Components

```
+-----------------------------------------------------------------------------------+
|                              PhishNetra Web Frontend                              |
|   +--------------------------+   +-----------------------+   +----------------+   |
|   |   SOAR Playbooks Page    |   |  Threat Hunting Lab   |   | Threat Feeds & |   |
|   | (/playbooks - visual     |   | (/hunting - 6-vector  |   |   Connectors   |   |
|   |  pipeline execution)     |   |  HAR/TLS/DOM sandbox) |   |  (/feeds)      |   |
|   +------------+-------------+   +-----------+-----------+   +--------+-------+   |
+----------------|-----------------------------|------------------------|-----------+
                 |                             |                        |
                 v                             v                        v
+-----------------------------------------------------------------------------------+
|                                Express API Gateway                                |
|   +--------------------------+   +-----------------------+   +----------------+   |
|   |  /api/playbooks          |   |  /api/hunting         |   | /api/connectors|   |
|   +------------+-------------+   +-----------+-----------+   +--------+-------+   |
+----------------|-----------------------------|------------------------|-----------+
                 |                             |                        |
                 v                             v                        v
+-----------------------------------------------------------------------------------+
|                             Core Defense Services                                 |
|                                                                                   |
|  [PlaybookOrchestrationEngine]      [ThreatHuntingService]     [ThreatConnectorHub]|
|   - Trigger Evaluator                - 6-Vector Query Parser    - TAXII 2.1 AIS   |
|     * VERDICT_THRESHOLD                * REGEX (Domain)         - MISP CIRCL      |
|     * BRAND_TARGET                     * IP_CIDR                - AlienVault OTX  |
|     * REGEX_MATCH                      * ASN Lookup             - AbuseIPDB       |
|     * MANUAL                           * JA3 SSL Hash           - Polling Worker  |
|   - Sequential Step Execution          * SHA256 File Hash       - Sync Lifecycle  |
|     * DNS RPZ Sinkhole Rule            * Brand Impersonation                      |
|     * Legal RFC 2142 Notice          - Deep Forensic Sandbox                      |
|     * Incident Case Auto-Creation      * HAR Network Waterfall                    |
|     * Webhook/SIEM Dispatch            * TLS Certificate Chain                    |
|     * Host Endpoint Isolation          * DOM Mutation Logs                        |
|   - Real-Time Audit & History                                                     |
+-----------------------------------------------------------------------------------+
```

---

## 3. Autonomous SOAR Playbook Engine

### Default Enterprise Playbooks
1. **Zero-Day Auto-Containment (`pb-001`)**:
   - **Trigger:** Phishing verdict >= 85
   - **Action Pipeline:**
     1. Inject BIND9/Unbound DNS RPZ sinkhole entry.
     2. Dispatch high-priority CEF/LEEF SIEM webhook alert.
     3. Auto-escalate to SOC incident case.
2. **Executive Brand Impersonation Takedown (`pb-002`)**:
   - **Trigger:** Brand target detected (e.g., Microsoft, Google, PayPal, Bank of America).
   - **Action Pipeline:**
     1. Formulate RFC 2142 automated legal abuse notice.
     2. Create priority SOC investigation case.
     3. Broadcast Slack/Webhook notification to Legal & SecOps teams.
3. **Credential Harvester Rapid Quarantine (`pb-003`)**:
   - **Trigger:** Regex match for login/credential harvest paths (`/(login|signin|account|verify|update).*auth/i`).
   - **Action Pipeline:**
     1. Push active DNS sinkhole block.
     2. Isolate internal host sessions accessing the malicious URI.
     3. Publish urgent security audit record.

### REST Endpoints
- `GET /api/playbooks` - List all configured playbooks.
- `GET /api/playbooks/:id` - Fetch detailed playbook definition.
- `POST /api/playbooks` - Create custom automated playbook.
- `PUT /api/playbooks/:id` - Update trigger thresholds or action steps.
- `DELETE /api/playbooks/:id` - Remove a playbook.
- `POST /api/playbooks/:id/trigger` - Manually dispatch playbook execution on target IOC.
- `GET /api/playbooks/:id/runs` - Retrieve audit run history and step timings.

---

## 4. Multi-Vector Threat Hunting Lab

### Query Capabilities
| Vector Type | Example Query | Description |
|-------------|---------------|-------------|
| `DOMAIN_REGEX` | `^.*-secure-(login|verify)\.xyz$` | Identifies malicious algorithmic naming conventions |
| `IP_CIDR` | `198.51.100.0/24` | Sweeps autonomous IP subnets for co-hosted phishing nodes |
| `ASN` | `AS13335` | Audits autonomous systems hosting threat infrastructure |
| `JA3_FINGERPRINT` | `e3b0c44298fc1c149afbf4c8996fb924` | Correlates TLS client signatures used by threat tools |
| `SHA256_HASH` | `a3f5b8c9d...` | Matches page resource hashes and payload drops |
| `BRAND_NAME` | `Microsoft` / `Chase` | Uncovers live impersonation campaigns |

### Deep Forensic Replay Sandbox
- **HAR Network Waterfall:** Live recording of all HTTP/HTTPS redirects, status codes, payload sizes, MIME types, and millisecond latencies.
- **TLS Certificate Chain Inspector:** Subject CN, SAN alt names, Issuer CA, key algorithms, serial numbers, and validity periods.
- **DOM Mutation Logs:** Real-time stream of suspicious DOM events (hidden password fields injected, obfuscated eval scripts, dynamic form action alterations).

---

## 5. Threat Intelligence Connectors

| Connector | Standard | Default Polling | Capabilities |
|-----------|----------|-----------------|--------------|
| **TAXII 2.1 AIS Server** | STIX 2.1 / TAXII 2.1 | 60 mins | Automated indicator sharing from cyber centers |
| **MISP CIRCL** | REST / PyMISP | 30 mins | Community IOC events, threat tags, and malware hashes |
| **AlienVault OTX** | Direct REST API | 120 mins | Community pulses, adversarial TTPs, and domain lists |
| **AbuseIPDB** | API v2 | 45 mins | High-confidence malicious IP reputation reports |

### REST Endpoints
- `GET /api/connectors` - List connector status, item counts, and sync history.
- `POST /api/connectors/:id/sync` - Trigger immediate sync cycle for a specific feed.
- `POST /api/connectors/sync-all` - Trigger asynchronous sync across all enabled feeds.
- `PATCH /api/connectors/:id/toggle` - Enable or disable background synchronization.

---

## 6. Verification & Automated Testing
- **Backend Test Suite:** `apps/api/tests/playbooks_and_hunting.test.ts`
- **Total Test Suites Passed:** 20 / 20 suites (110 / 110 tests in `apps/api`, 180 total across monorepo).
- **Frontend Verification:** TypeScript strict checks + Vite production bundle passed.
