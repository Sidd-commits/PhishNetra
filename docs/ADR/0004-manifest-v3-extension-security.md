# ADR 0004: Manifest V3 Browser Extension & Real-Time Threat Mitigation

## Status
**Accepted**

## Context
Google Chrome's Manifest V3 specification deprecates persistent background pages in favor of event-driven Service Workers, imposes restrictions on remotely hosted code, and requires strict declarative request handling.

## Decision
We engineered `apps/extension` around Manifest V3 standards:
1. **Event-Driven Service Worker (`serviceWorker.ts`):**
   - Intercepts navigation events asynchronously via `chrome.tabs.onUpdated` and `chrome.webNavigation.onCommitted`.
2. **Two-Tier Threat Evaluation:**
   - **Tier 1 (<5ms Local Heuristics):** In-memory Shannon entropy, Punycode/homoglyph detection, IP address check without network latency.
   - **Tier 2 (Full API Scan):** Async payload transmission to `POST /api/analyze` for 8-layer deep inspection.
3. **Zero Silent Redirects Invariant:**
   - Instead of silently redirecting users away from suspected threats, the extension injects a high-security interstitial warning screen.
   - Users are presented with clear choices: (1) Return to Safety, (2) Inspect Technical SOC Evidence, (3) Temporary Session Bypass.

## Consequences
- **Positive:** Complies fully with Chrome Web Store Manifest V3 security standards.
- **Positive:** Protects users with zero client-side latency via local pre-filtering.
- **Trade-off:** Service workers can be terminated when idle; state is persisted in `chrome.storage.local`.
