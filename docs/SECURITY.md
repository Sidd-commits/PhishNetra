# PhishNetra — Security & Zero-Trust Architecture

**Project:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Milestone:** Implementation 3 (Secure Web Content Analysis & AI-Assisted Phishing Detection)

---

## 1. Zero-Trust UX & Analysis Principle

In traditional web scanners, a valid green lock icon or active HTTPS certificate is often misleadingly equated with website security. **PhishNetra enforces a strict Zero-Trust principle:**
> **No single signal determines trust.**  
> A valid TLS certificate only proves cryptographic transport encryption between client and server — over 80% of active phishing infrastructure uses free automated TLS certificates (e.g. Let's Encrypt, Cloudflare). Similarly, clean reputation feeds or familiar brand styling alone do not guarantee safety. A target with valid HTTPS can still be scored **HIGH RISK** or **PHISHING** if its domain age is young (< 30 days), DNS resolves to suspicious infrastructure, forms submit credentials cross-origin, or brand-domain inconsistency is detected.

---

## 2. Secure Web Analysis & Browser Isolation (Implementation 3)

With Implementation 3, PhishNetra actively inspects webpage content, DOM structure, forms, and behavioral signals while maintaining absolute server isolation.

### 2.1 Server-Side Request Forgery (SSRF) Boundary
Under no circumstances does the primary Express API process issue direct HTTP/fetch/axios requests to arbitrary user-supplied target URLs. All content acquisition is delegated to an isolated Python analyzer service (`services/ml`) operating with defense-in-depth network restrictions:

1. **IP Range Blacklisting:**
   - IPv4 Private (RFC 1918): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - IPv4 Loopback (RFC 1122): `127.0.0.0/8`
   - IPv4 Link-Local (RFC 3927): `169.254.0.0/16` (including AWS/GCP/Azure Cloud Metadata `169.254.169.254`)
   - IPv4 Carrier-Grade NAT (RFC 6598): `100.64.0.0/10`
   - IPv4 Multicast / Reserved: `224.0.0.0/4`, `240.0.0.0/4`, `0.0.0.0/8`
   - IPv6 Loopback / Link-Local / Unique Local: `::1`, `fe80::/10`, `fc00::/7`, `::ffff:0:0/96`
2. **Alternative IP Notation Normalization:**
   - Detects and normalizes decimal integer IPs (e.g. `2130706433`), hexadecimal IPs (e.g. `0x7f.0.0.1`), octal representations (e.g. `0177.0.0.1`), and IPv4-mapped IPv6 representations before network execution.

### 2.2 Pre-Flight DNS Resolution & DNS Rebinding Protection
Host validation alone is insufficient against Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks. PhishNetra executes pre-flight socket resolution (`socket.getaddrinfo`) to verify all resolved IP addresses against restricted CIDRs. If any resolved IP is prohibited, the target is blocked immediately prior to socket allocation.

### 2.3 Redirect Chain Monitoring & Re-Validation
Attackers frequently use open redirects or multi-hop redirects to bypass initial URL scanners.
- PhishNetra tracks the full redirect chain: `originalUrl` → `redirects[]` → `finalUrl`.
- Every redirect destination is re-validated against the SSRF engine before following.
- Hard redirect limit is enforced (`MAX_REDIRECTS = 5`).
- Attempts to redirect to private IPs, loopback, or cloud metadata endpoints are immediately aborted.

### 2.4 Browser-Context Isolation & Safe Acquisition
- **Ephemeral Browser Contexts:** Playwright Chromium spins up a fresh, disposable `BrowserContext` for every individual inspection and destroys it immediately upon completion.
- **No Persistence:** No cookies, local storage, indexedDB, or cached credentials persist across requests.
- **Route-Level Interception:** Route handlers intercept network requests during navigation, blocking unauthorized protocols (`file://`, `ftp://`, `gopher://`) and verifying destination IPs.
- **Capability Lockdown:** Local filesystem access, host APIs, developer machine secrets, and browser extensions are completely disabled.

### 2.5 Resource & Execution Limits
To guard against resource exhaustion, denial-of-service, and infinite loops:
- **Navigation Timeout:** Max 10,000ms.
- **Total Acquisition Timeout:** Max 12,000ms.
- **Max Response Payload:** 5 MB.
- **Max Page Resources:** 100 requests.
- **Max DOM Nodes:** 5,000 elements.

### 2.6 Strict Passive Analysis Boundary
PhishNetra operates exclusively as an inspection engine. It does **NOT**:
- Type credentials or fake usernames into input fields.
- Click submit buttons or trigger form submissions.
- Execute interactive payment workflows.
- Download or execute binary/executable payloads (`.exe`, `.sh`, `.msi`, `.bat`).

### 2.7 Screenshot & Artifact Handling
- Screen captures are processed in-memory or via strictly ephemeral local buffers.
- Sanitized metadata (dimensions, format, byte size) is stored with analysis records.
- Persisted screenshot binaries are never exposed directly to unauthenticated endpoints.

---

## 3. Threat Intelligence Provider Isolation

1. **Provider Key Protection:**  
   External API credentials (such as VirusTotal or PhishTank) are loaded exclusively from environment variables and never logged or exposed to the client.
2. **Graceful Fallback on Missing Keys:**  
   If API keys are absent, providers return `status: NOT_CONFIGURED`, and the Risk Engine dynamically redistributes weights across remaining active layers without failing the analysis.
3. **Safe Timeouts:**  
   All external queries (RDAP, DNS, Threat Feeds) are protected by strict `2000ms - 2500ms` timeouts using `Promise.race` and `Promise.allSettled`.

