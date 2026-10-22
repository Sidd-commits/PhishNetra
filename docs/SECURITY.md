# PhishNetra — Security Model & Zero-Trust Architecture

**Project:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Specification:** Complete System Security & Privacy Reference  

---

## 1. Zero-Trust Core Principle

Traditional perimeter defenses often equate a valid HTTPS certificate or familiar brand logo with trustworthiness. Over 85% of active phishing infrastructure leverages automated, free TLS certificates (Let's Encrypt, Cloudflare) and clones legitimate CSS frameworks.

**PhishNetra enforces a non-negotiable Zero-Trust invariant:**
> **No single signal determines trust.**  
> A target destination with a valid TLS certificate and clean legacy blacklists will still be classified as **PHISHING** or **HIGH RISK** if its domain age is newly registered (< 14 days), DNS resolves to suspicious hosting providers, form actions point cross-origin to untrusted endpoints, or brand domain mismatches are discovered.

---

## 2. Browser Extension Privacy & Security Boundary (Manifest V3)

The PhishNetra Chrome Extension is designed with defense-in-depth privacy controls:

1. **Minimal Manifest V3 Permissions:**
   - Strictly limited to `activeTab`, `tabs`, `storage`, `scripting`, and `alarms`.
   - Omnipresent web history permissions (`history`) and cookie interception permissions (`cookies`) are **forbidden**.
2. **Zero Credential Harvesting:**
   - Content scripts never inspect, read, log, or transmit form input values, passwords, keystrokes, or session tokens.
   - Analysis only extracts structural attributes (`<form action="...">`, `<input type="...">`) to evaluate cross-origin credential harvesting.
3. **Non-Silent Interception Principle:**
   - The browser extension never performs automated silent redirects.
   - Interstitial warnings present transparent, explainable evidence and require an intentional user decision (Return to Safety, Inspect Evidence, or Conscious Bypass).
4. **Local Heuristics Fail-Safe:**
   - Sub-millisecond client-side checks in the service worker ensure that even if backend network connectivity is interrupted, obvious homoglyph deceptions, IP hostnames, and suspicious top-level domains are immediately flagged.

---

## 3. Email Attachment Parsing Safety Boundary

To address malware and phishing links embedded in email attachments without exposing the server or client to code execution risks:

1. **Passive Pure-JS Parsing:**
   - Attachments (`PDF`, `HTML`, `DOCX`, `TXT`, `EML`) are inspected exclusively using pure-JavaScript string and stream parsers.
   - **No native binaries, document office suites, or shell tools are spawned.**
2. **Strict Non-Execution of Active Content:**
   - Document macros, embedded OLE objects, JavaScript action hooks, and binary executables (`.exe`, `.dll`, `.bat`, `.vbs`) are **never executed**.
3. **Size Ceilings & Memory Protection:**
   - Strict 10MB file size ceiling per attachment.
   - Processing is bound to synchronous memory streams with regex catastrophic-backtracking defenses.
4. **Distinction Between Clean and Unparseable Files:**
   - `NO_SUSPICIOUS_URLS_FOUND`: Indicates successful parsing where zero URLs or only verified benign URLs were detected.
   - `UNABLE_TO_ANALYZE`: Indicates an unsupported binary format, password protection, or malformed stream. **Unparseable attachments are never marked as safe.**

---

## 4. Server-Side Request Forgery (SSRF) Protection

All remote webpage fetching is delegated to an isolated Python analyzer service (`services/ml`) operating with multi-stage network restrictions:

1. **Restricted IP Ranges (Pre-Flight & Socket Hook):**
   - **IPv4 Loopback (RFC 1122):** `127.0.0.0/8`
   - **IPv4 Private Subnets (RFC 1918):** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - **IPv4 Link-Local (RFC 3927):** `169.254.0.0/16` (including AWS/GCP/Azure Cloud Metadata `169.254.169.254`)
   - **IPv4 Carrier-Grade NAT (RFC 6598):** `100.64.0.0/10`
   - **IPv4 Multicast / Reserved:** `224.0.0.0/4`, `240.0.0.0/4`, `0.0.0.0/8`
   - **IPv6 Loopback / Link-Local / Unique Local:** `::1`, `fe80::/10`, `fc00::/7`, `::ffff:0:0/96`
2. **Alternative IP Notation Normalization:**
   - Normalizes decimal integer IPs (`2130706433`), hex (`0x7f.0.0.1`), octal (`0177.0.0.1`), and IPv4-mapped IPv6 representations before DNS resolution.
3. **Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding Defenses:**
   - Target hostname resolution executes pre-flight socket verification. If any IP in the resolved round-robin belongs to a restricted subnet, connection is aborted before TCP handshake.
4. **Redirect Hop Re-Validation:**
   - Every redirect step (`301`, `302`, `307`, `308`) is re-checked against the SSRF engine.
   - Hard maximum limit of 5 redirect hops. Attempts to pivot from a public URL to an internal IP trigger immediate connection termination.

---

## 5. Sandboxed Webpage Inspection Boundary

1. **Disposable Browser Contexts:**
   - Playwright Chromium creates an ephemeral `BrowserContext` per inspection and destroys it immediately upon page evaluation.
   - No cookies, local storage, or session states persist across analyses.
2. **Execution & Resource Limits:**
   - Navigation timeout: 10,000ms.
   - Total acquisition timeout: 12,000ms.
   - Maximum response payload: 5MB.
   - Maximum DOM elements: 5,000 nodes.
3. **Passive Inspection Only:**
   - PhishNetra does not click buttons, submit credentials, trigger downloads, or interact with external payment gateways.

---

## 6. Threat Intelligence Provider Isolation & Fail-Safe Rules

1. **Credential Isolation:** External API tokens are read exclusively from backend environment variables and are never sent to the client.
2. **Graceful Degradation:** If an external intelligence provider is unavailable or rate-limited, the system marks the provider as `UNAVAILABLE` and dynamically redistributes layer weights across active signals.
3. **Fail-Safe Invariant:** Missing intelligence or upstream timeouts never result in an automatic `SAFE` verdict.
