# PhishNetra — Threat Simulation Lab & Red Team Attack Replay Sandbox

## Overview & Architecture

The **PhishNetra Threat Simulation Lab & Automated Defense Benchmark** provides an enterprise-grade synthetic attack execution and verification environment. It allows SOC analysts, security engineers, and Red Teams to safely replay advanced phishing, evasive infrastructure, and social engineering payloads against the PhishNetra 8-layer Zero-Trust detection architecture without exposing live assets or external hosts.

---

## Key Capabilities

### 1. 12 Distinct Attack Vector Families

The simulation engine models 12 threat vector families defined in `@phishnetra/shared`:

| Attack Vector | Category | Detection Mechanics & Layer Interception |
| :--- | :--- | :--- |
| `SPEAR_PHISH_BRAND_IMPERSONATION` | Credential Theft | Layer 8 (Brand) + Layer 7 (Form) + Zero-Trust Override |
| `UNICODE_HOMOGLYPH_PUNYCODE` | Lexical Evasion | Layer 1 (URL) + Layer 2 (Domain) + Cyrillic lookalike confusable decoding |
| `SUBDOMAIN_BRAND_PACKING` | Structural Deception | Layer 1 (URL) subdomain entropy & brand keyword hierarchy |
| `COMBOSQUATTING_LOOKALIKE` | Infrastructure Masquerading | Layer 2 (Domain) Damerau-Levenshtein distance & brand catalog matching |
| `CREDENTIAL_HARVEST_CROSS_ORIGIN` | DOM Weaponization | Layer 7 (Content/Form) cross-origin POST action detection |
| `FAST_FLUX_DNS_EVASION` | Dynamic Infrastructure | Layer 3 (DNS) multi-IP geographic disperse resolution with low TTL |
| `SSRF_METADATA_PROBE` | Server-Side Evasion | Layer 3 (DNS/Network) link-local `169.254.169.254` proactive blocking |
| `SOCIAL_ENGINEERING_URGENCY` | Psychological Manipulation | Layer 7 (Content) NLP urgency & financial lure keyword scoring |
| `PERCENT_ENCODING_HEX_OBFUSCATION` | Delimiter Hiding | Layer 1 (URL Canonicalization) percent-encoding normalization & entropy |
| `SHORTENER_REDIRECT_CHAIN` | Intermediate Redirection | Layer 1 (URL) shortener catalog detection & unwinding |
| `EXPIRED_SELFSIGNED_TLS` | Transport Layer Masquerade | Layer 4 (TLS) certificate validity, expiration, & issuer verification |
| `DEFANGED_RAW_IOC_EVASION` | Defanged Payload Masquerading | Ingestion normalization (`hxxp`, `[.]`, `hXXps`) & recursive unwrapping |

---

## Pre-Configured Red Team Attack Scenarios

The simulator comes pre-loaded with curated attack scenarios mimicking real-world cyber threat actor campaigns:

1. **Microsoft 365 Urgent Credential Re-Authentication (`preset_ms365_urgency`)**
   - *Target:* `https://login.microsoftonline.com-auth-verify.security-update.internal/auth/login`
   - *Techniques:* Subdomain packing, Cross-Origin POST, Brand Impersonation, Social Engineering Urgency
   - *Expected Verdict:* `PHISHING` (Critical Risk 92/100)

2. **PayPal Cyrillic Homoglyph Invoice Scam (`preset_paypal_homoglyph`)**
   - *Target:* `https://xn--paypl-qqa.com/invoice/pay?ref=urgent_transfer`
   - *Techniques:* Unicode confusable homoglyph (`а` vs `a`), Brand Impersonation
   - *Expected Verdict:* `PHISHING` (Critical Risk 89/100)

3. **Apple ID iCloud Session Timeout Alert (`preset_apple_subdomain`)**
   - *Target:* `https://appleid.apple.com.manage-devices-portal.xyz/verify`
   - *Techniques:* Subdomain Brand Packing, Unencrypted/Suspicious TLS
   - *Expected Verdict:* `PHISHING` (High Risk 86/100)

4. **AWS Metadata SSRF Attack Probe (`preset_aws_metadata_ssrf`)**
   - *Target:* `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   - *Techniques:* SSRF Cloud Metadata Probe, RFC 3927 Link-Local Targeting
   - *Expected Verdict:* `PHISHING` (Critical Risk 100/100) — Zero-Trust Proactive Block

5. **Chase Bank Fraud Alert Combosquatted Portal (`preset_chase_combosquat`)**
   - *Target:* `https://chasebank-security-center-support.online/resolve`
   - *Techniques:* Combosquatting, Brand Abuse, Urgent Financial Lures
   - *Expected Verdict:* `PHISHING` (Critical Risk 88/100)

6. **Fast-Flux DNS Bulletproof Evasion Network (`preset_fast_flux_dns`)**
   - *Target:* `http://secure-update-patch-node88.net/download/payload.exe`
   - *Techniques:* Dynamic IP rotation, ultra-low DNS TTL, Fast-flux botnet relay
   - *Expected Verdict:* `PHISHING` (High Risk 82/100)

---

## Automated 48-Scenario Defense Validation Benchmark

The defense benchmark suite executes **4 synthetic trials per vector family (48 total scenarios)** to calculate regression and performance metrics:

- **Mitigation Rate (%):** Percentage of synthetic attack payloads neutralized (Target: >= 95%).
- **Mean Processing Latency (ms):** Sub-millisecond pipeline latency verification.
- **Zero-Trust Invariant Integrity (%):** Verification that high-confidence brand mismatch, SSRF, and credential harvesting overrides cannot be bypassed.
- **Vector-by-Vector Breakdown:** Detailed score aggregation per threat technique.

---

## REST API Endpoints

### 1. List Attack Scenario Presets
```http
GET /api/simulation/presets
Authorization: Bearer <TOKEN>
```

### 2. Execute Attack Simulation
```http
POST /api/simulation/run
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "presetId": "preset_ms365_urgency",
  "targetUrl": "https://login.microsoftonline.com-auth-verify.security-update.internal/auth/login",
  "targetBrand": "Microsoft",
  "vectorType": "SPEAR_PHISH_BRAND_IMPERSONATION",
  "simulateBrowser": true
}
```

### 3. Run Automated Defense Benchmark
```http
POST /api/simulation/benchmark
Authorization: Bearer <TOKEN>
```

---

## UI Threat Simulation Studio

Accessible at `/simulation`:
1. **Interactive Attack Sandbox Tab:**
   - Preset selector and custom attack vector configurator.
   - Live 8-layer detection canvas displaying per-layer scores, weights, findings, and Zero-Trust overrides.
   - Extracted threat evidence breakdown and automated mitigation actions (RPZ sinkholing, firewall rules, abuse notices).
2. **Automated Defense Benchmark Tab:**
   - 1-click execution across all 48 test scenarios.
   - Metric cards: Mitigation Rate, Scenarios Evaluated, Evasions, Zero-Trust Invariant Integrity, Mean Pipeline Latency.
   - Vector-by-vector breakdown grid with color-coded risk distribution.
