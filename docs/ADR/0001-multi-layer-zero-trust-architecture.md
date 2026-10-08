# ADR 0001: Multi-Layer Zero-Trust Phishing Detection Architecture

## Status
**Accepted**

## Context
Traditional phishing detection systems rely on single-point indicators, such as naive keyword matching or static domain reputation blacklists. Modern cyber threat actors bypass single-point defenses through technique stacking: combining Unicode homoglyphs, fresh lookalike domains (<24h old), free TLS certificates, link-local metadata SSRF pivots, and legitimate cloud CDNs.

## Decision
We implemented an 8-layer Zero-Trust detection architecture where no single indicator is trusted implicitly:
1. **Layer 1 (URL Lexical)**: Entropy calculation, hex obfuscation, delimiter abuse.
2. **Layer 2 (Domain & RDAP)**: Registrable domain age classification (<30d, 30-90d, >365d), registrar privacy.
3. **Layer 3 (DNS & IP)**: Fast-flux detection, ASN clustering, private RFC 1918 / RFC 3927 SSRF defense.
4. **Layer 4 (TLS / SSL)**: Handshake parameters, certificate issuer, SAN matching, expiration.
5. **Layer 5 (Reputation Feeds)**: Asynchronous multi-provider aggregation (URLhaus, OpenPhish, PhishTank).
6. **Layer 6 (ML Classification)**: 18-dimensional lexical feature probability score with Random Forest ensemble.
7. **Layer 7 (Web Content DOM)**: Ephemeral headless Chromium sandbox extracting form action destinations, password/card fields, external script origins.
8. **Layer 8 (Brand Consistency)**: Visual and textual brand catalog matching verifying official domain ownership.

### Zero-Trust Invariant Overrides
When critical invariant rules are violated (e.g., Brand Domain Mismatch with Credential Harvesting, or SSRF Link-Local targeting), the system executes a deterministic override, forcing the verdict to `PHISHING` or `CRITICAL` regardless of low composite scores on benign layers.

## Consequences
- **Positive:** Dramatically reduces False Negatives on novel zero-day phishing campaigns.
- **Positive:** Provides transparent, layer-attributed evidence items for SOC analysts.
- **Trade-off:** Multi-layer evaluation requires asynchronous concurrency and multi-tier caching (Redis/Memory) to maintain sub-second response times.
