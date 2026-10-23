# PhishNetra — Demo URL Catalog & Presentation Cheat Sheet

**Academic Project:**  
*PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation*  
**Catalog Version:** 2.0  
**Generated At:** Fri, 23 Oct 2026 18:41:59 GMT  
**Total Curated URLs:** 388

---

## 1. Quick Start for Presentation & Live Demonstrations

Use this cheat sheet during viva, panel reviews, or project exhibitions to quickly copy and test URLs directly into:
1. **Single URL Real-Time Scanner** (`http://localhost:5173/analyze` or API `POST /api/analyze`)
2. **High-Throughput Batch Scanner** (`http://localhost:5173/batch` or drag-and-drop `demo_urls/batch_upload_samples.csv`)
3. **Chrome MV3 Extension** (Navigate to any phishing URL to trigger the pre-navigation interstitial threat barrier)

---

## 2. Category 1: Benign / Safe URLs (Demonstrating Zero False-Positive Accuracy)

These URLs showcase PhishNetra's **Brand Self-Identity Primacy** and **Institutional Dampeners**, proving the engine does not flag legitimate logins, app store references, or educational portals as phishing.

| Target URL | Category | Expected Verdict | Why PhishNetra Validates It |
| :--- | :--- | :---: | :--- |
| `https://internshala.com/chat/c-125923166?filter=all` | Internship Chat | **SAFE** (Risk < 10) | App Store badges matched via ecosystem dampener; self-identity primacy overrides generic keywords. |
| `https://erp.iitd.ac.in/login.htm` | Academic ERP | **SAFE** (Risk < 25) | Accredited `.ac.in` educational registrar dampener; same-origin login form classified as INFO. |
| `https://www.iitb.ac.in/en/academics/academic-calendar` | University Portal | **SAFE** (Risk < 10) | Verified institutional ccTLD with clean TLS certificates and authoritative nameservers. |
| `https://gemini.google.com/app` | Cloud AI Portal | **SAFE** (Risk < 10) | Legitimate sub-domain of Google; brand dampener active; valid high-reputation domain age. |
| `https://github.com/login` | Developer Auth | **SAFE** (Risk < 15) | Microsoft/GitHub authoritative certificate alignment; same-origin credential submission. |
| `https://www.paypal.com/signin` | Payment Gateway | **SAFE** (Risk < 15) | Authoritative PayPal registrar (`paypal.com`); official brand identity matches domain name. |
| `https://netbanking.hdfcbank.com/netbanking/` | Online Banking | **SAFE** (Risk < 20) | Authoritative Indian banking registrar with EV/OV certificate alignment. |
| `https://incometax.gov.in/iec/foportal/` | Government Portal | **SAFE** (Risk < 10) | Indian sovereign government `.gov.in` domain; trusted public authority. |
| `https://en.wikipedia.org/wiki/Phishing` | Knowledge | **SAFE** (Risk < 5) | Informational encyclopedic portal without credential harvesting forms. |

---

## 3. Category 2: Suspicious URLs (Demonstrating Multi-Signal Amber Warnings)

These URLs test PhishNetra's ability to issue nuanced warning verdicts (**SUSPICIOUS**, risk scores 35–69) when domains exhibit mixed signals or potential evasion tactics.

| Target URL | Category | Expected Verdict | Suspicious Signals Detected |
| :--- | :--- | :---: | :--- |
| `https://bit.ly/3xSampleTestLink` | URL Shortener | **SUSPICIOUS** | Conceals destination URI; Layer 1 triggers redirector resolution warning. |
| `http://auth-worker-node.duckdns.org/sync` | Dynamic DNS | **SUSPICIOUS** | DuckDNS public dynamic IP mapper; domain age variable; unverified host identity. |
| `http://temp-portal-2026.no-ip.biz/login` | Dynamic DNS | **SUSPICIOUS** | Free dynamic DNS host combining credential keyword with unverified subdomain. |
| `https://sub-node-gateway.ngrok-free.app/` | Ephemeral Tunnel | **SUSPICIOUS** | Temporary tunneling service often abused for rapid C2 or staging. |
| `http://urgent-notification-update.top/read.php` | Low-Rep TLD | **SUSPICIOUS** | High-abuse `.top` registry with urgent social engineering keywords. |
| `http://portal-secure-verification.work/notice` | Low-Rep TLD | **SUSPICIOUS** | Disposable `.work` TLD with stacked security terms. |

---

## 4. Category 3: Benchmark Phishing Evasion Vectors (Demonstrating Layer Capabilities)

These URLs showcase PhishNetra's **8-layer deterministic threat engine** and **Zero-Trust overrides**.

| Vector & Target URL | Target Brand | Expected Verdict | Detection Layer & Mechanism |
| :--- | :---: | :---: | :--- |
| **Cyrillic Homoglyph**<br>`http://xn--ggle-55da.com/login` | **Google** | **PHISHING**<br>(85-100) | **Layer 0/1:** Decodes Punycode to `gооgle.com` (using Cyrillic 'о' U+043E); detects lookalike spoofing. |
| **Punycode Lookalike**<br>`http://xn--pple-43d.com/appleid/verify` | **Apple** | **PHISHING**<br>(85-100) | **Layer 0/1:** Cyrillic `аpple.com` (U+0430); triggers homoglyph brand impersonation Zero-Trust override. |
| **Combosquatting on .xyz**<br>`https://paypal-security-verification.xyz/login` | **PayPal** | **PHISHING**<br>(80-95) | **Layer 1 & 8:** Combines brand `paypal` + keywords on low-reputation `.xyz` TLD; Brand Domain Mismatch. |
| **Bank Combosquatting**<br>`http://chase-online-account-verify.top/signin.php` | **Chase** | **PHISHING**<br>(80-95) | **Layer 1 & 8:** Financial brand token injection on `.top` disposable registrar. |
| **M365 Credential Harvest**<br>`http://microsoft-office365-password-reset.live/login`| **Microsoft** | **PHISHING**<br>(80-95) | **Layer 8:** Brand domain mismatch against official `microsoft.com` authority. |
| **Indian Banking Phishing**<br>`http://sbi-yono-kyc-verification.top/portal` | **SBI** | **PHISHING**<br>(80-95) | **Layer 8:** Impersonates SBI YONO banking; triggers zero-tolerance banking brand spoof override. |
| **Subdomain Brand Stacking**<br>`https://login.microsoftonline.com.account-auth-security.xyz/oauth` | **Microsoft** | **PHISHING**<br>(85-100) | **Layer 1:** Prepends legitimate FQDN as deep subdomain of attacker apex `account-auth-security.xyz`. |
| **RFC 3986 Userinfo Trick**<br>`https://www.paypal.com@phish-login-credentials.net/signin` | **PayPal** | **PHISHING**<br>(85-95) | **Layer 1:** Detects `@` authority delimiter trick routing HTTP traffic to external host. |
| **SSRF Link-Local Metadata**<br>`http://169.254.169.254/latest/meta-data/` | **AWS / Cloud** | **PHISHING**<br>(90-100) | **Layer 3:** Strict RFC 1918 / Cloud link-local metadata IP filter blocks SSRF exfiltration. |
| **SSRF Private IP Probe**<br>`http://192.168.1.1/admin-setup.php` | **Internal Network** | **PHISHING**<br>(90-100) | **Layer 3:** Private network address blocked to protect internal intranet perimeters. |
| **AiTM Reverse Proxy**<br>`https://auth-sec-verify-microsoft.account-portal.xyz/login`| **Microsoft** | **PHISHING**<br>(85-100) | **Layer 15:** Evilginx/Modlishka reverse proxy heuristic flags cookie tunneling. |

---

## 5. Category 4: Live OpenPhish Real-World Threat Feed Samples

Scraped live from public threat intelligence feeds (e.g. OpenPhish). These represent live adversary infrastructure currently circulating across the internet.

1. `https://www.in-patrika.vercel.app/`
2. `https://amiable-someone-703260.framer.app/`
3. `https://9ervp-qmf-k9yx8-d15udr-omxlc.pages.dev/`
4. `http://sp28ct-gurem-biz-qazel-zotek.pages.dev/`
5. `https://hopeful-package-333853.framer.app/`
6. `http://sp30ct10-zulreko-biz-kuremi.pages.dev/`
7. `http://653-f66w-ecv-90xi-rp3ec-ev79.pages.dev/`
8. `http://amt-hbegzz-vl70jk-gbb-y48ck.pages.dev/`
9. `https://gcc-7f9acq-ppx1t-efke-945.pages.dev/`
10. `https://sp30ct10-ravkilo-biz-zumeti.pages.dev/`
11. `http://du8d-0fiet-c1s5-8qwt5-r1f.pages.dev/`
12. `https://sp30ct10-rumvemi-biz-zakaro.pages.dev/`
13. `http://qlq3f-9pwx8-xv2-621ljm-5b49o.pages.dev/`
14. `http://sp30ct10-varkilo-biz-kumaro.pages.dev/`
15. `http://sp30ct10-kavzuni-biz-munelo.pages.dev/`

*(Full list of 300 live feed URLs saved in `demo_urls/live_feed_phishing_urls.txt`)*

---

## 6. Files in this Directory

| Filename | Description | Usage |
| :--- | :--- | :--- |
| **`README.md`** | This comprehensive visual cheat sheet | Presentation reference & viva guide |
| **`demo_catalog.json`** | Complete structured JSON metadata catalog | Programmatic testing & documentation |
| **`batch_upload_samples.csv`** | 30 curated URLs in RFC 4180 CSV format | Drag-and-drop into Batch Scanner UI (`/batch`) |
| **`batch_upload_samples.json`** | 30 curated URLs formatted for API payload | Send via `POST /api/batch` |
| **`safe_urls.txt`** | 45+ verified benign URLs (one per line) | Quick copy-paste for benign tests |
| **`suspicious_urls.txt`** | 20+ suspicious/warning URLs | Quick copy-paste for amber threshold tests |
| **`phishing_attack_vectors.txt`** | 20+ weaponized attack vector URLs with annotations | Demonstrate specific detection layers |
| **`live_feed_phishing_urls.txt`** | 300 live OpenPhish URLs | Demonstrate real-world threat detection |
