# PhishNetra — REST API & Multi-Layer Reference

**Current Version:** `v0.2.0` (Milestone 2: Multi-Layer Threat Intelligence)  
**Base URL:** `http://localhost:5000/api`

---

## 1. Authentication Endpoints

### `POST /auth/register`
Creates a new analyst account.
- **Request Body:**
  ```json
  {
    "name": "SOC Analyst",
    "email": "analyst@phishnetra.dev",
    "password": "SecurePassword2026!"
  }
  ```
- **Response (201 Created):**
  ```json
  {
    "user": {
      "id": "uuid",
      "name": "SOC Analyst",
      "email": "analyst@phishnetra.dev",
      "role": "USER",
      "createdAt": "2026-09-03T16:00:00.000Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsIn..."
  }
  ```

### `POST /auth/login`
Authenticates existing credentials.

---

## 2. Multi-Layer Threat Analysis Endpoints

### `POST /analyze`
Performs comprehensive multi-layer threat analysis on candidate URL.

- **Request Body:**
  ```json
  {
    "url": "https://paypal.com/signin"
  }
  ```

- **Response (200 OK):**
  ```json
  {
    "analysisId": "e674b97e-d2e8-4ff4-a78b-d53cb1e0b12e",
    "url": "https://paypal.com/signin",
    "normalizedUrl": "https://paypal.com/signin",
    "verdict": "SAFE",
    "riskScore": 5.4,
    "riskLevel": "LOW",
    "confidence": 0.88,
    "mlProbability": 0.02,
    "layerStatuses": {
      "URL": "SUCCESS",
      "DOMAIN": "SUCCESS",
      "DNS": "SUCCESS",
      "TLS": "SUCCESS",
      "REPUTATION": "PARTIAL",
      "ML": "SUCCESS"
    },
    "layers": {
      "url": {
        "status": "SUCCESS",
        "canonicalUrl": "https://paypal.com/signin",
        "hostname": "paypal.com",
        "entropy": 3.86,
        "isShortener": false,
        "isPunycode": false,
        "features": { ... }
      },
      "domain": {
        "status": "SUCCESS",
        "domain": "paypal.com",
        "registrableDomain": "paypal.com",
        "domainAgeDays": 9912,
        "domainAgeCategory": "> 365 days",
        "registrar": "MarkMonitor Inc.",
        "isPrivacyProtected": false
      },
      "dns": {
        "status": "SUCCESS",
        "resolvedIps": ["151.101.3.1", "151.101.195.1"],
        "ipv4Count": 2,
        "ipv6Count": 0,
        "hasMx": true,
        "ipDetails": [
          { "ip": "151.101.3.1", "version": "IPv4", "org": "Fastly", "country": "US" }
        ]
      },
      "tls": {
        "status": "SUCCESS",
        "hasTls": true,
        "certificateValid": true,
        "certificateExpired": false,
        "hostnameMatches": true,
        "issuer": "DigiCert Inc",
        "daysUntilExpiry": 210,
        "zeroTrustWarning": "ZERO-TRUST PRINCIPLE: HTTPS encrypts transport, NOT website safety."
      },
      "reputation": {
        "status": "SUCCESS",
        "isListedMalicious": false,
        "reputationScore": 0,
        "providers": [
          { "providerName": "URLhaus (abuse.ch)", "status": "SUCCESS", "malicious": false }
        ]
      },
      "ml": {
        "status": "SUCCESS",
        "phishingProbability": 0.02,
        "confidence": 0.96,
        "modelVersion": "v0.1.0-baseline"
      }
    },
    "evidence": [
      {
        "layer": "DOMAIN",
        "featureKey": "established_domain",
        "featureValue": "27 years (9912 days)",
        "severity": "INFO",
        "description": "Domain has established history (9912 days old).",
        "source": "RDAP",
        "confidence": 0.95
      }
    ],
    "createdAt": "2026-09-03T16:50:00.000Z"
  }
  ```

### `GET /analyze/history`
Returns paginated historical scans for the authenticated analyst.

### `GET /analyze/:id`
Retrieves full investigation report by analysis ID.
