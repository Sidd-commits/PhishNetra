# PhishNetra Chrome Manifest V3 Browser Extension & Real-Time Threat Mitigation

## 1. Overview & Architecture

The **PhishNetra Browser Extension** provides real-time, browser-level protection against phishing, credential harvesting, brand impersonation, and zero-day malicious domains. Built strictly adhering to the **Google Chrome Manifest V3** specifications, it implements proactive threat detection with zero degradation to user browsing speed.

```
+-----------------------------------------------------------------------------------+
|                            User Browser Session                                    |
|                                                                                   |
|  [Tab Navigation]                                                                 |
|         │                                                                         |
|         ▼                                                                         |
|  [Background Service Worker] ──► (1) Local Lexical Heuristics (<5ms)             |
|         │                        • Shannon entropy, Punycode, suspicious TLDs    |
|         │                                                                         |
|         ├──► (2) Client-Side Cache Check (chrome.storage.local, TTL: 15m)        |
|         │                                                                         |
|         └──► (3) Async PhishNetra Core Engine Query (/api/analyze)                |
|                    │                                                              |
|                    ▼                                                              |
|         [Action Badge Manager] ──► [Green: 0-39 | Amber: 40-74 | Red: 75-100]    |
|                    │                                                              |
|                    ▼                                                              |
|         [Zero Silent Redirects Security Policy]                                   |
|         ├── Verdict: PHISHING (Score >= 75) ──► Full-Screen Interstitial Overlay |
|         └── Verdict: SUSPICIOUS (Score 40-74) ─► Floating Warning Banner         |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Security Capabilities

### A. Zero Silent Redirects Policy
In compliance with enterprise security requirements, PhishNetra **never silently or automatically redirects** user traffic. Instead, when critical phishing or credential theft indicators are identified:
1. An un-bypassable DOM security barrier (**Threat Interstitial**) is injected into the active tab.
2. The user is presented with three transparent choices:
   - **Return to Safety (Recommended)**: Navigates back or closes the dangerous tab.
   - **Inspect SOC Evidence**: Opens the deep-linked domain dossier on the PhishNetra SOC Console.
   - **I Understand the Risks (Continue Anyway)**: Grants a temporary session bypass (`chrome.storage.session`) without whitelisting the domain globally.

### B. Instantaneous Local Lexical Heuristics (<5ms)
Before the backend network request resolves, the background worker performs an instant lexical analysis assessing:
- **Raw IP Hostnames**: `http://192.168.1.1/...`
- **Punycode / Homoglyph Characters**: `xn--...` (Cyrillic/Greek lookalikes)
- **High-Risk TLDs**: `.xyz`, `.top`, `.tk`, `.ml`, `.icu`, `.buzz`, `.rest`, `.click`
- **Excessive Subdomain Count**: `paypal.security.login.attacker.com`
- **High Shannon Entropy**: Randomly generated or DGA domains (>3.8 entropy)
- **Misleading '@' Delimiters**: `google.com@malicious-domain.com`

### C. Multi-Layer Threat Action Badge
The extension badge dynamically reflects live tab risk:
- **Green (`10-39`)**: Domain safe and verified.
- **Amber (`40-74`)**: Suspicious characteristics detected.
- **Red (`75-100` / `90+`)**: Active phishing threat intercepted.
- **Emerald (`OK`)**: Whitelisted trusted domain.
- **Blue (`•••`)**: Active multi-tier scanning in progress.
- **Gray (`IGN`)**: Session threat bypass granted.

---

## 3. Installation & Developer Setup

### Step 1: Build the Extension
```bash
# In apps/extension directory
npm install
npm run build
```
The production bundle will be generated in `apps/extension/dist/`.

### Step 2: Load into Google Chrome / Chromium
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** toggle in the upper-right corner.
3. Click **Load unpacked**.
4. Select the directory: `PhishNetra/apps/extension/dist/`.
5. The **PhishNetra SOC Extension** will appear in the extensions toolbar.

---

## 4. SOC Popup Console Features

Clicking the PhishNetra shield icon in the browser toolbar opens the high-density SOC console:
- **Live Threat Meter**: Real-time composite risk gauge (0 to 100).
- **Layer-by-Layer Verification**:
  - 🌐 **Lexical / URL Heuristics**
  - 🏛️ **RDAP / Registration Age**
  - ⚡ **Threat Feeds & IP Reputation**
  - 🔍 **DOM Credential Form Harvester**
  - 🤖 **AI Machine Learning Engine**
- **One-Click Threat Reporting**: Direct submission of false positives or new phishing campaigns into the PhishNetra SOC moderation queue.
- **One-Click Domain Whitelist**: Quick trusting of enterprise internal domains.
- **Deep Investigation Link**: Launches the complete domain dossier on `http://localhost:5173/analysis`.

---

## 5. Options & Configuration (`options.html`)

Accessible via right-clicking the extension icon -> **Options**:
- **Backend API URL**: Configurable REST endpoint (default: `http://localhost:5000/api`).
- **SOC Web Dashboard URL**: Base URL for SOC analysts (default: `http://localhost:5173`).
- **Mitigation Threshold**: Configurable slider (50% to 95%) controlling when the full-page interstitial triggers.
- **Trusted Whitelist**: Manage custom approved enterprise domains.
- **Purge Threat Cache**: Instant invalidation of client-side cache entries.

---

## 6. Verification & Test Suite

The extension features unit and integration tests covering heuristic evaluation and storage persistence:
```bash
# Run extension test suite
npm run test:extension
```
- `tests/heuristics.test.ts`: Validates entropy calculation, IP hostname flags, Cyrillic punycode, suspicious TLDs, and benign baseline URLs.
- `tests/storage.test.ts`: Validates settings persistence, caching TTL expiry, domain whitelisting, and session bypass logic.
