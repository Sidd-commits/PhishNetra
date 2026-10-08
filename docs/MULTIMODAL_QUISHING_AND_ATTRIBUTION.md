# Multimodal Quishing Defense, Threat Actor Attribution Matrix & FAIR Cyber Risk

**Document Version:** 1.0.0  
**Phase:** Milestone 17 — Advanced Multimodal Countermeasures, APT Attribution & Financial Risk Modeling  
**Coverage:** QR Code (Quishing) De-weaponization, OCR Visual Lure Extraction, Threat Actor Attribution (MITRE ATT&CK & Diamond Model), Quantitative Cyber Risk (FAIR Model)

---

## 1. Executive Summary

Milestone 17 equips PhishNetra with next-generation multimodal defense capabilities, adversary intelligence profiling, and actuarial cyber risk quantification:

1. **Multimodal Quishing (QR Code Phishing) Defense Engine (`QuishingDefenseService.ts` / `/api/quishing`):**
   Neutralizes QR codes in raster images and documents that bypass Secure Email Gateways (SEGs). Unmasks dynamic shorteners, extracts visual OCR social-engineering lures, and generates autonomous Passkey/FIDO2 step-up challenges and Snort NIDS signatures.
2. **Threat Actor Attribution Matrix (`ThreatActorAttributionService.ts` / `/api/attribution`):**
   Correlates observed campaign infrastructure, targeted brands, ASNs, and MITRE ATT&CK TTPs against detailed profiles of major state-sponsored and cybercrime syndicates (e.g., **Scattered Spider / UNC3944**, **APT28 / Fancy Bear**, **APT29 / Midnight Blizzard**, **Lazarus Group**, **FIN7**), outputting Adversary Diamond Models and TTP heatmaps.
3. **Quantitative Cyber Risk (FAIR Framework) Engine (`CyberRiskQuantificationService.ts` / `/api/risk-quantification`):**
   Calculates Expected Annual Loss (ALE) in currency ($/year), Loss Event Frequency (LEF), workforce vulnerability ratios, and PhishNetra Defense ROI Multiples using the industry-standard Factor Analysis of Information Risk (FAIR) mathematical model.

```
+----------------------------------------------------------------------------------------------------+
|                                     PhishNetra Milestone 17                                       |
+------------------------------------+-----------------------------------+---------------------------+
|    Multimodal Quishing Defense     |      Threat Actor Attribution     |   FAIR Cyber Risk Studio  |
|  - Barcode Decoding & Parsing      |  - Scattered Spider / UNC3944     |  - Loss Event Frequency   |
|  - Dynamic Shortener Traps         |  - APT28, APT29, Lazarus, FIN7    |  - Vulnerability Ratio    |
|  - Visual OCR Urgency Extraction   |  - MITRE ATT&CK TTP Heatmap       |  - Expected Annual Loss   |
|  - FIDO2 / Passkey Step-Up         |  - Adversary Diamond Model        |  - Mitigated Exposure ($) |
|  - Automated Snort NIDS Generator  |  - High-Confidence Correlation    |  - Probabilistic (10-90%) |
+------------------------------------+-----------------------------------+---------------------------+
```

---

## 2. Multimodal Quishing (QR Code Phishing) Defense

### 2.1 Threat Mechanics & Detection Gap
Traditional email and web scanners parse plain-text hyperlinks. Threat actors exploit this blind spot by rendering phishing links inside QR code images embedded in PDFs, PNGs, and JPEG invoices. The victim is prompted to scan the code with a smartphone camera, which:
- Evades corporate network perimeter inspection and Secure Email Gateways.
- Shifts execution to an unmanaged personal mobile device devoid of corporate Endpoint Detection and Response (EDR) agents.
- Delivers AiTM reverse proxies or credential harvesting login portals.

### 2.2 Ingestion & Heuristic Pipeline
`QuishingDefenseService` processes image sources and contextual lure texts through four validation stages:
1. **Barcode / QR Decoding:** Extracts raw payload URLs and identifies dynamic tracking shorteners (e.g. `qrco.de`, `l.ead.me`, `me-qr.com`, `bit.ly`).
2. **Visual Lure OCR Extraction:** Identifies high-urgency keywords embedded in images ("Scan to update Authenticator app", "Session expired", "Account locked", "Invoice overdue").
3. **Multi-Signal Risk Calibration:** Synthesizes QR detection, dynamic shortener indicators, targeted brand markers, and credential keywords into a calibrated risk score (0-100).
4. **Autonomous Countermeasures:**
   - Enforces origin-bound FIDO2 Passkey step-up authentication.
   - Triggers email gateway image attachment quarantine.
   - Emits Snort/Suricata network signature blocking HTTP requests to the target domain.

---

## 3. Threat Actor Attribution Matrix

### 3.1 Tracked Adversary Profiles
PhishNetra maintains structured threat profiles mapping known cybercrime and APT groups:

| Actor ID | Name & Aliases | Origin | Primary Targets | Key TTPs | Signatures |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SCATTERED_SPIDER` | UNC3944, Octo Tempest, 0ktapus | Transnational | Identity Providers, Telecoms, Cloud | T1566.002, T1621, T1583.001 | Evilginx Okta reverse proxy, SMS phishing helpdesk lures |
| `APT28` | Fancy Bear, Strontium | Russia (GRU) | Government, Defense, NATO | T1566.002, T1583.008, T1071.001 | OAuth Device Authorization Grant abuse, Round-robin DNS C2 |
| `APT29` | Midnight Blizzard, Nobelium | Russia (SVR) | Cloud Tenants, Foreign Ministries | T1078.004, T1566.002, T1538 | Azure App Registration consent theft, Password spraying |
| `LAZARUS_GROUP` | Hidden Cobra, Labyrinth Chollima | North Korea | Crypto Exchanges, Fintech, Aerospace | T1566.001, T1204.002, T1027 | Recruiter PDF lures, Malicious npm packages, Web3 wallet theft |
| `FIN7` | Sangria Tempest, Carbanak | Eastern Europe | Hospitality, Retail POS, Healthcare | T1566.002, T1059.003, T1055 | Spoofed supplier food order invoices, Obfuscated LNK memory injectors |

### 3.2 Adversary Diamond Model Synthesis
For each candidate domain, `ThreatActorAttributionService` builds a four-node Diamond Model:
- **Adversary:** Threat group name and nation-state / syndicate origin.
- **Capability:** Primary weaponization and delivery tooling (e.g. Evilginx SSO reverse proxy).
- **Infrastructure:** Identified ASNs, registrars, and dynamic TLDs.
- **Victimology:** Targeted industry verticals and organizational roles.

---

## 4. Quantitative Cyber Risk (FAIR Framework) Engine

### 4.1 Mathematical Formulation
The FAIR model replaces subjective "high/medium/low" guesses with calibrated financial probability:

$$\text{Vulnerability Ratio } (V) = \text{Susceptibility Rate} \times (1 - \text{Control Effectiveness})$$

$$\text{Loss Event Frequency } (\text{LEF}) = \text{Annual Phishing Attempts} \times V$$

$$\text{Primary Loss Expected} = \text{LEF} \times \text{Cost per Compromised Credential}$$

$$\text{Secondary Loss Expected} = \min(1.0,\, \text{LEF} \times P_{\text{regulatory}}) \times (\text{Max Fine} \times 0.20)$$

$$\text{Expected Annual Loss } (\text{ALE}) = \text{Primary Loss} + \text{Secondary Loss}$$

$$\text{Mitigated Loss} = \text{ALE}_{\text{unmitigated}} - \text{ALE}$$

$$\text{Defense ROI Multiple} = \frac{\text{Mitigated Loss}}{\text{Annual Platform Cost}}$$

### 4.2 Probabilistic Loss Distribution
Calculates 10th percentile (optimistic), 50th percentile (median), and 90th percentile (worst-case breach) loss projections to support executive board-level risk management.

---

## 5. REST API Reference

### Quishing Defense (`/api/quishing`)
- `POST /api/quishing/scan`: Inspects image URL or text for QR codes and visual lures.
- `GET /api/quishing/samples`: Returns pre-seeded Quishing attack scenarios.

### Threat Actor Attribution (`/api/attribution`)
- `GET /api/attribution/actors`: Lists all tracked adversary profiles.
- `GET /api/attribution/actors/:id`: Retrieves full profile by actor ID.
- `POST /api/attribution/match`: Matches target domain, ASN, and TTPs against the attribution matrix.

### FAIR Cyber Risk (`/api/risk-quantification`)
- `GET /api/risk-quantification/defaults`: Returns baseline risk parameters.
- `POST /api/risk-quantification/calculate`: Computes quantitative loss exposure, ALE, and defense ROI.

---

## 6. Monorepo Quality Gates & Verification

- **API Test Suites:** 24/24 suites passing, **151/151 tests (100%)**.
- **Python ML Tests:** 8/8 suites passing, **58/58 tests (100%)**.
- **Chrome Extension Tests:** 2/2 suites passing, **12/12 tests (100%)**.
- **Vite Web Production Bundle:** Clean build, **0 TypeScript errors**.
- **Total Monorepo Tests:** **221 / 221 passing (100%)**.
