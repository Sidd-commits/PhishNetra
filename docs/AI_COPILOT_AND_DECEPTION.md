# PhishNetra AI SOC Co-Pilot, Active Canary Deception Engine & External Attack Surface Management (EASM)

## 1. Executive Summary
Milestone 14 introduces **Autonomous AI SOC Co-Pilot Assistant**, **Active Canary Deception Tripwires & Decoys**, and **External Attack Surface Management with Certificate Transparency Logs Radar**.

---

## 2. Architecture & Ecosystem

```
+-----------------------------------------------------------------------------------+
|                              PhishNetra Web Frontend                              |
|   +--------------------------+   +-----------------------+   +----------------+   |
|   |    AI SOC Co-Pilot       |   | Canary Deception Hub  |   | Attack Surface |   |
|   |  (/copilot - agentic     |   | (/deception - honeypot|   | (/attack-surface|  |
|   |   triage & reasoning)    |   |  tripwire telemetry)  |   |  EASM & CT Logs)|  |
|   +------------+-------------+   +-----------+-----------+   +--------+-------+   |
+----------------|-----------------------------|------------------------|-----------+
                 |                             |                        |
                 v                             v                        v
+-----------------------------------------------------------------------------------+
|                                Express API Gateway                                |
|   +--------------------------+   +-----------------------+   +----------------+   |
|   |  /api/copilot            |   |  /api/deception       |   |/api/attack-    |   |
|   |                          |   |                       |   | surface        |   |
|   +------------+-------------+   +-----------+-----------+   +--------+-------+   |
+----------------|-----------------------------|------------------------|-----------+
                 |                             |                        |
                 v                             v                        v
+-----------------------------------------------------------------------------------+
|                             Core Defense Services                                 |
|                                                                                   |
|  [ThreatCopilotService]         [CanaryDeceptionService]   [AttackSurfaceService] |
|   - Multi-Layer Signal Triage    - Canary Token Generator   - Perimeter Asset Hub |
|   - Chain-of-Thought Reasoning     * HTTP Web Bug (1x1 GIF)   * Apex & Subdomains |
|   - Rule & Query Synthesizer       * DNS Tripwire             * IPs & Ports       |
|     * SIEM KQL (Sentinel)          * Decoy Credentials        * Brand Keywords    |
|     * Snort/Suricata NIDS          * Anti-Scraping Beacon   - CT Logs Radar       |
|     * Threat Hunt Regex            * Fake API Keys          - Real-Time Typosquat |
|     * BIND9 DNS RPZ Sinkhole     - Public Beacon Listener     Interception        |
|   - MITRE ATT&CK Mapping         - JA3 / Header Forensics   - Auto-Quarantine     |
+-----------------------------------------------------------------------------------+
```

---

## 3. AI SOC Co-Pilot Assistant

### Capabilities
- **Root Cause & Forensic Breakdown:** Ingests live threat verdicts, 8-layer confidence values, and evidence keys to generate human-readable technical breakdowns.
- **Cross-Layer Query Synthesis:** Compiles exact regex syntax, KQL queries, and ASN pivots to find dormant phishing campaign nodes.
- **NIDS & Sinkhole Rule Compilation:** Drop-in Snort/Suricata rules and BIND9 DNS RPZ sinkholes.
- **MITRE ATT&CK Correlation:** Maps behaviors to ATT&CK techniques (T1566.002 Spearphishing Link, T1583.001 Acquire Domains, T1608.005 Link Target Deception).

### REST Endpoints
- `GET /api/copilot/templates` - Pre-configured enterprise prompt templates.
- `POST /api/copilot/chat` - Process analyst prompt with multi-step reasoning and artifact generation.

---

## 4. Active Canary Deception Engine

### Supported Canary Token Types
1. **HTTP Web Bug (`HTTP_WEB_BUG`):** Transparent 1x1 GIF placed in internal wikis/apps (`/api/deception/beacon/:token.gif`).
2. **DNS Tripwire (`DNS_TRIPWIRE`):** DNS canary subdomain triggers alert upon DNS resolution attempt.
3. **Decoy Corporate Credentials (`DECOY_CREDENTIAL`):** Planted in public repositories to identify credential harvesting and unauthorized test logins.
4. **Cloned Page Anti-Scraping Tripwire (`CLONED_LOGIN_BEACON`):** Injected JavaScript DOM beacon executing when attackers scrape and host cloned phishing kits.
5. **Fake API Key (`FAKE_API_KEY`):** Decoy bearer keys triggering high-priority SOC alerts.

### REST Endpoints
- `GET /api/deception/tokens` - List all deployed canary tokens.
- `POST /api/deception/tokens` - Create new canary token with deploy snippet.
- `GET /api/deception/tokens/:id` - Fetch token details.
- `PATCH /api/deception/tokens/:id/status` - Toggle active/disabled status.
- `GET /api/deception/triggers` - List recorded attacker trigger events.
- `GET /api/deception/beacon/:tokenString` - Public beacon endpoint (returns 1x1 GIF).
- `POST /api/deception/beacon/:tokenString` - Public beacon endpoint (for JS beacon postbacks).

---

## 5. External Attack Surface Management & CT Logs Radar

### Capabilities
- **Perimeter Asset Discovery:** Continuous monitoring of corporate apex domains, subdomains, ingress IPs, and exposed ports.
- **Certificate Transparency (CT) Stream:** Ingests new SSL/TLS certificates issued worldwide in real-time, detecting homoglyphs and typosquats targeting corporate brands (e.g. `microsoft-security-verify-365.com`).
- **Auto-Quarantine Integration:** Automatically triggers DNS RPZ sinkholing and incident escalation for high-confidence typosquats observed in CT logs.

### REST Endpoints
- `GET /api/attack-surface/assets` - List all monitored perimeter assets.
- `POST /api/attack-surface/assets` - Register new monitored asset.
- `DELETE /api/attack-surface/assets/:id` - Remove asset from perimeter.
- `GET /api/attack-surface/ct-logs` - Stream Certificate Transparency log entries.
- `POST /api/attack-surface/scan` - Trigger live perimeter sweep.

---

## 6. Verification & Automated Test Coverage
- **API Test Suite:** `apps/api/tests/copilot_and_deception.test.ts` (11 / 11 tests passing).
- **Monorepo Pass Rate:** 191 / 191 tests passing (100%).
- **Frontend Verification:** `tsc && vite build` bundled cleanly with zero errors.
