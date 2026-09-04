# PhishNetra — SSRF Threat Model & Defense-in-Depth

**Milestone:** Implementation 3 (Secure Web Content Analysis & AI-Assisted Phishing Detection)  
**Component:** `services/ml/app/security/ssrf.py`

---

## 1. Threat Overview & Target Assets

Server-Side Request Forgery (SSRF) occurs when a web scanner or analysis engine can be coerced into sending crafted requests to unexpected destinations. Because PhishNetra analyzes untrusted URLs submitted by users, SSRF represents a tier-1 critical security risk.

### Protected Assets:
1. **Cloud Instance Metadata Services (IMDS):** AWS/GCP/Azure link-local endpoints (`http://169.254.169.254/latest/meta-data/`) containing IAM temporary session credentials.
2. **Localhost & Internal Loopback Services:** Redis, database ports (5432, 3306, 27017), internal APIs, and management dashboards bound to `127.0.0.1` or `localhost`.
3. **Private Intranet Infrastructure:** Internal microservices and RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
4. **Local Host Filesystem & System Resources:** Sensitive system files (`/etc/passwd`, Windows registry/SAM, `.env` files).

---

## 2. Attack Vectors & PhishNetra Mitigations

### Vector 1: Direct Private & Loopback IP Access
* **Attack:** Submitting `http://127.0.0.1:8000/admin`, `http://localhost`, `http://10.0.0.1`, or `http://[::1]`.
* **Mitigation:** IP CIDR validation matches destination addresses against comprehensive standard IPv4/IPv6 private, loopback, carrier-grade NAT, multicast, and link-local ranges:
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918)
  - `127.0.0.0/8`, `0.0.0.0/8` (RFC 1122)
  - `169.254.0.0/16` (RFC 3927)
  - `100.64.0.0/10` (RFC 6598)
  - `224.0.0.0/4`, `240.0.0.0/4`
  - `::1`, `fe80::/10`, `fc00::/7`, `::ffff:0:0/96`
* **Outcome:** Blocked prior to connection with `status: BLOCKED`.

### Vector 2: IP Representation Obfuscation (Bypass Tricks)
* **Attack:** Submitting non-standard IP formats to evade simple string pattern filters:
  - Decimal integer IP: `http://2130706433/` (evaluates to `127.0.0.1`)
  - Hexadecimal IP: `http://0x7f000001/` or `http://0x7f.0x00.0x00.0x01/`
  - Octal IP: `http://0177.0.0.1/`
  - IPv4-mapped IPv6: `http://[::ffff:127.0.0.1]/`
* **Mitigation:** `ssrf.py` normalizes all integer, hexadecimal, octal, and mapped representations into canonical standard `ipaddress.IPv4Address` / `ipaddress.IPv6Address` objects before applying subnet containment checks.
* **Outcome:** Blocked immediately.

### Vector 3: DNS Rebinding (Time-of-Check to Time-of-Use TOCTOU)
* **Attack:** An attacker controls a domain `evil-rebind.com` whose DNS server returns a public IP during the validation phase with TTL=0, but returns `127.0.0.1` or `169.254.169.254` when the browser actually connects.
* **Mitigation:**
  1. Pre-flight DNS resolution inspects all resolved A and AAAA records across the system resolver.
  2. Route-level interception in the Playwright/HTTPX acquisition engine checks the resolved IP of every request at the socket boundary before allowing data transfer.
* **Outcome:** Blocked if any resolved address falls within prohibited ranges.

### Vector 4: Multi-Hop Redirection to Internal Resources
* **Attack:** Public URL `http://public-attacker.com/redirect` returns HTTP 302 pointing to `http://169.254.169.254/latest/meta-data/`.
* **Mitigation:**
  - Automated redirect following is monitored hop-by-hop.
  - Every redirect response intercepts the `Location` header and re-runs SSRF validation and DNS resolution before the next request is dispatched.
  - Maximum redirect limit is capped at 5 hops.
* **Outcome:** Redirection chain halts immediately with `BLOCKED`.

### Vector 5: Non-HTTP Scheme Exploitation
* **Attack:** Submitting `file:///etc/passwd`, `gopher://127.0.0.1:6379/`, `ftp://internal/`, `data:text/html,...`.
* **Mitigation:** Scheme validation restricts requests strictly to `http` and `https`. All other schemes are rejected before parser initialization.

---

## 3. Residual Limitations & Defense-in-Depth Recommendations

While application-level SSRF mitigations in PhishNetra provide robust defenses against standard and advanced bypasses, enterprise production deployments should enforce additional infrastructure-level controls:
1. **Network Egress Filtering:** Isolate the analyzer microservice in a dedicated VPC / network namespace with egress firewall rules preventing connections to `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `169.254.169.254`.
2. **IMDSv2 Enforcement:** Require token-based session authentication for AWS metadata (`HttpTokens=required`) with hop limit = 1 so containerized processes cannot reach instance credentials.
3. **Container Sandbox (Docker / gVisor):** Run browser analysis workers in read-only scratch filesystems with no host network access (`--network=isolated_net`).
