# PhishNetra — API Specification (Milestone 1)

This document specifies the REST API contracts for the Node.js API server (`http://localhost:5000`) and the Python FastAPI ML microservice (`http://localhost:8000`).

---

## Part 1: Application REST API (`apps/api`)

Base URL: `http://localhost:5000/api`

### 1. Authentication Endpoints

#### `POST /auth/register`
Creates a new analyst account and issues a session JWT.

- **Request Body:**
  ```json
  {
    "name": "Jane Analyst",
    "email": "analyst@phishnetra.dev",
    "password": "SecurePassword123!"
  }
  ```
- **Success Response (`201 Created`):**
  ```json
  {
    "user": {
      "id": "c1f7a8b9-...",
      "name": "Jane Analyst",
      "email": "analyst@phishnetra.dev",
      "role": "USER",
      "createdAt": "2026-09-03T16:00:00.000Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6..."
  }
  ```

---

#### `POST /auth/login`
Authenticates existing analyst credentials.

- **Request Body:**
  ```json
  {
    "email": "analyst@phishnetra.dev",
    "password": "SecurePassword123!"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "user": {
      "id": "c1f7a8b9-...",
      "name": "Jane Analyst",
      "email": "analyst@phishnetra.dev",
      "role": "USER",
      "createdAt": "2026-09-03T16:00:00.000Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6..."
  }
  ```

---

#### `POST /auth/logout`
Clears session cookies and invalidates current client state.

- **Success Response (`200 OK`):**
  ```json
  {
    "message": "Logged out successfully"
  }
  ```

---

#### `GET /auth/me`
Retrieves authenticated user profile. Requires `Authorization: Bearer <token>`.

- **Success Response (`200 OK`):**
  ```json
  {
    "user": {
      "id": "c1f7a8b9-...",
      "name": "Jane Analyst",
      "email": "analyst@phishnetra.dev",
      "role": "USER",
      "createdAt": "2026-09-03T16:00:00.000Z"
    }
  }
  ```

---

### 2. Threat Analysis Endpoints

#### `POST /analyze`
Submits a target URL for feature extraction, ML classification, risk scoring, and evidence persistence.

- **Headers:** `Authorization: Bearer <token>` (Optional/Recommended)
- **Request Body:**
  ```json
  {
    "url": "http://192.168.1.50/secure-paypal-login/verify.php"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "analysisId": "8f3e2b1a-4d5c-...",
    "url": "http://192.168.1.50/secure-paypal-login/verify.php",
    "normalizedUrl": "http://192.168.1.50/secure-paypal-login/verify.php",
    "verdict": "PHISHING",
    "riskScore": 92.4,
    "riskLevel": "CRITICAL",
    "confidence": 0.90,
    "mlProbability": 0.95,
    "evidence": [
      {
        "featureKey": "has_ip_address",
        "featureValue": "true",
        "severity": "HIGH",
        "description": "URL uses a raw IP address instead of a recognized domain name.",
        "contribution": 0.35
      },
      {
        "featureKey": "suspicious_keyword_count",
        "featureValue": 3,
        "severity": "HIGH",
        "description": "URL contains 3 sensitive/credential keywords (e.g. login, verify, banking, secure).",
        "contribution": 0.30
      }
    ],
    "features": {
      "url_length": 49,
      "hostname_length": 12,
      "path_length": 36,
      "query_length": 0,
      "subdomain_count": 0,
      "has_ip_address": 1,
      "has_https": 0,
      "special_char_count": 5,
      "digit_count": 10,
      "hyphen_count": 2,
      "at_symbol_count": 0,
      "double_slash_in_path": 0,
      "encoded_char_count": 0,
      "suspicious_keyword_count": 3,
      "entropy": 4.12,
      "tld_in_subdomain": 0,
      "port_in_url": 0,
      "tld_length": 0
    },
    "createdAt": "2026-09-03T16:05:00.000Z"
  }
  ```

---

#### `GET /analyze/history`
Returns paginated past analyses for the authenticated user.

- **Headers:** `Authorization: Bearer <token>`
- **Query Params:** `limit` (default: 20), `offset` (default: 0)
- **Success Response (`200 OK`):**
  ```json
  {
    "items": [
      {
        "id": "8f3e2b1a-...",
        "url": "https://google.com",
        "verdict": "SAFE",
        "riskScore": 8.5,
        "riskLevel": "LOW",
        "confidence": 0.95,
        "createdAt": "2026-09-03T16:00:00.000Z"
      }
    ],
    "total": 1
  }
  ```

---

#### `GET /analyze/:id`
Retrieves a full analysis report by ID including all recorded evidence items.

- **Success Response (`200 OK`):**
  Returns complete `AnalysisResponse` object.

---

### 3. Health Endpoint

#### `GET /health`
Returns system status and connectivity of Postgres and the ML Microservice.

- **Success Response (`200 OK`):**
  ```json
  {
    "status": "healthy",
    "timestamp": "2026-09-03T16:00:00.000Z",
    "service": "PhishNetra Node.js REST API",
    "version": "0.1.0",
    "dependencies": {
      "database": "healthy",
      "mlService": {
        "status": "connected"
      }
    }
  }
  ```

---

## Part 2: ML Inference Microservice (`services/ml`)

Base URL: `http://localhost:8000`

### `POST /api/v1/predict`
- **Request Body:** `{"url": "https://example.com"}`
- **Response:** Extracted feature vector, `phishing_probability`, `confidence`, `predicted_label`, and `inference_time_ms`.

### `POST /api/v1/features`
- **Request Body:** `{"url": "https://example.com"}`
- **Response:** Raw extracted 18+ feature vector dictionary.

### `GET /health`
- **Response:** Service readiness and model version metadata.
