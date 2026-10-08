# ADR 0002: Isolated Browser Sandbox & SSRF Defense Architecture

## Status
**Accepted**

## Context
Inspecting dynamic web page content, JavaScript redirects, and DOM login forms is essential for detecting credential harvesting. However, fetching arbitrary user-supplied URLs exposes internal infrastructure to Server-Side Request Forgery (SSRF) attacks, cloud metadata exfiltration (`169.254.169.254`), and browser-level remote code execution.

## Decision
We implemented a sandboxed content acquisition pipeline decoupled from the primary REST API:
1. **Pre-flight SSRF Validation (`ssrf.py`):**
   - Prohibits loopback (`127.0.0.0/8`, `::1`), private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and link-local metadata (`169.254.0.0/16`).
   - Normalizes and decodes obfuscated IP representations (octal, decimal, hexadecimal integer notations).
   - Defends against DNS rebinding by validating resolved IP addresses before and during transport connections.
2. **Ephemeral Playwright Browser Sandbox (`page_fetcher.py`):**
   - Chromium contexts run with `--no-sandbox`, `--disable-dev-shm-usage`, and custom user-agent strings.
   - Resource loading limits: strict 10-second timeout, 5MB payload caps, route-level blocking of multimedia assets (`image`, `media`, `font`).
   - Clean ephemeral teardown after DOM snapshot extraction.

## Consequences
- **Positive:** Complete isolation prevents malicious web payloads from compromising backend servers.
- **Positive:** Blocks credential and IAM token exfiltration from cloud environments.
- **Trade-off:** Headless browser instantiation consumes memory; mitigated by reusing browser pools and fallback to secure HTTPX clients.
