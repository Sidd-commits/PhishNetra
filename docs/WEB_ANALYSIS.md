# PhishNetra — Secure Web Analysis & Browser Isolation Specification

**Milestone:** Implementation 3 (Secure Web Content Analysis & AI-Assisted Phishing Detection)  
**Component:** `services/ml/app/analyzer/`

---

## 1. Overview & Objective

PhishNetra Implementation 3 enables deep web content inspection to detect client-side phishing indicators that cannot be identified from lexical URL structure alone (such as fake login dialogs, credential harvesting forms submitting cross-origin, deceptive brand titles on foreign domains, and hidden redirection iframes).

Because inspecting arbitrary malicious web destinations presents severe security risks (SSRF, cloud credential theft, browser exploits, denial of service), PhishNetra employs an **Isolated Browser Architecture** with strict network containment and a passive-only inspection policy.

---

## 2. Browser Architecture & Execution Pipeline

```text
Target URL Request
       │
       ▼
[ Pre-Flight Validation ] ───► Prohibited IP / Format Error ──► Blocked (Status: BLOCKED)
       │ (SSRF check & DNS resolution)
       ▼
[ Ephemeral Browser Context ] (Playwright Chromium)
       │ • Route-level SSRF interception
       │ • Cookies & cache disabled
       │ • Strict timeouts (10s nav, 12s overall)
       ▼
[ Controlled Navigation & Redirects ]
       │ • Follow max 5 hops
       │ • Re-validate every hop IP
       ▼
[ Passive DOM & Network Extraction ]
       │ • DOM Metrics & Structure (Nodes, Forms, Scripts, IFrames)
       │ • Form Destinations & Field Types
       │ • Static JavaScript Heuristics
       │ • Brand Impersonation & Phishing Keywords
       │ • Viewport Visual Metadata
       ▼
[ Ephemeral Context Destruction ] (Browser context closed immediately)
       │
       ▼
[ 20-Dim Feature Vector & Risk Evaluation ]
```

---

## 3. Controlled Page Acquisition Pipeline

1. **URL Sanitization & Validation:**
   - Normalizes protocol (`http` / `https`).
   - Rejects non-HTTP schemes (`file://`, `data:`, `javascript:`, `ftp://`, `gopher://`).
   - Normalizes alternative IP notations (hex, octal, decimal).
2. **Pre-flight DNS Rebinding Resolution:**
   - Resolves target hostname via `socket.getaddrinfo`.
   - Checks every returned IP against RFC 1918, RFC 1122, RFC 3927 (AWS/GCP/Azure metadata `169.254.169.254`), and IPv6 private blocks.
3. **Sandbox Acquisition:**
   - Playwright Chromium creates an isolated `BrowserContext` with no persistent state.
   - Route-level network interception filters every subresource request.
   - If Playwright cannot launch in a restricted worker environment, the pipeline falls back gracefully to a sandboxed HTTPX client with full SSRF streaming protections.
4. **Context Teardown:**
   - The browser page and context are destroyed inside a `finally` block to prevent resource leaks.

---

## 4. Redirect Monitoring

PhishNetra records every hop in the redirection chain:
- **`originalUrl`**: The initial candidate target.
- **`redirectChain`**: Sequential list of intermediate URLs traversed.
- **`finalUrl`**: The landing destination where content was extracted.
- **`redirectCount`**: Integer count of redirection hops.

**Security Constraint:** Each intermediate hop destination is parsed and resolved against the SSRF validation engine before following. Any redirect targeting a private or reserved network triggers an immediate `BLOCKED` status.

---

## 5. Network Observation

During page rendering, passive metadata is collected without capturing sensitive payloads:
- Total network requests initiated.
- Number of unique remote domains contacted.
- External domain resources vs internal same-origin resources.
- External script references and inline script count.
- External iframe embed sources.

---

## 6. Resource Limits & Safety Parameters

| Parameter | Limit | Purpose |
| :--- | :--- | :--- |
| `NAVIGATION_TIMEOUT` | 10,000 ms | Prevents slowloris and infinite loading loops. |
| `OVERALL_TIMEOUT` | 12,000 ms | Hard cap on total analysis execution time. |
| `MAX_REDIRECTS` | 5 | Prevents circular redirect exhaustion. |
| `MAX_RESPONSE_SIZE` | 5 MB | Caps incoming memory allocation for large payloads. |
| `MAX_RESOURCES` | 100 requests | Prevents resource starvation via heavy media. |
| `MAX_DOM_NODES` | 5,000 nodes | Caps DOM parser tree processing depth. |

---

## 7. Passive Inspection Policy (Zero Page Interaction)

The analyzer is strictly an observational engine. The isolated worker:
- **NEVER** enters usernames, passwords, test credentials, or fake tokens into forms.
- **NEVER** clicks submit buttons or triggers AJAX form submissions.
- **NEVER** executes interactive authorization flows (OAuth, SAML, CAPTCHA bypass).
- **NEVER** downloads or executes binary executables (`.exe`, `.sh`, `.msi`, `.dll`).
- **NEVER** accesses the local filesystem or environment secrets.
