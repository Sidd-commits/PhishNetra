# PhishNetra — Security & Zero-Trust Architecture

**Project:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Milestone:** Milestone 2 (Multi-Layer Threat Intelligence)

---

## 1. Zero-Trust UX & Analysis Principle

In traditional web scanners, a valid green lock icon or active HTTPS certificate is often misleadingly equated with website security. **PhishNetra enforces a strict Zero-Trust principle:**
> **No single layer establishes implicit trust.**  
> A valid TLS certificate only proves cryptographic transport encryption between client and server — over 80% of active phishing infrastructure uses free automated TLS certificates (e.g. Let's Encrypt, Cloudflare). A target with valid HTTPS can still be scored **HIGH RISK** or **PHISHING** if its domain age is young (< 30 days), DNS resolves to suspicious infrastructure, or lexical tokens indicate credential harvesting.

---

## 2. Server-Side Request Forgery (SSRF) Boundary & Isolation

1. **No Arbitrary Web Page Crawling in Milestone 2:**  
   PhishNetra strictly avoids downloading raw HTML/DOM bodies from candidate URLs on the primary API server.
2. **Passive DNS Inspection:**  
   DNS resolution uses standard operating system resolver promises without following redirects or issuing HTTP requests.
3. **Private Network Address (RFC1918) Detection:**  
   If a target URL or its resolved DNS entries map to loopback or intranet ranges (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), the Risk Engine immediately flags the target with a **CRITICAL** indicator and refuses further socket inspection.
4. **Non-Intrusive TLS Handshakes:**  
   TLS inspection connects solely to the TLS handshake layer on port 443 with a 3000ms timeout and immediately closes the socket after retrieving the peer certificate chain (`socket.getPeerCertificate()`).

---

## 3. Threat Intelligence Provider Isolation

1. **Provider Key Protection:**  
   External API credentials (such as VirusTotal or PhishTank) are loaded exclusively from environment variables and never logged or exposed to the client.
2. **Graceful Fallback on Missing Keys:**  
   If API keys are absent, providers return `status: NOT_CONFIGURED`, and the Risk Engine dynamically redistributes weights across remaining active layers without failing the analysis.
3. **Safe Timeouts:**  
   All external queries (RDAP, DNS, Threat Feeds) are protected by strict `2000ms - 2500ms` timeouts using `Promise.race` and `Promise.allSettled`.
