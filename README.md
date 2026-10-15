# PhishNetra 🛡️

> **A Multi-Layered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation**

[![Node.js](https://img.shields.io/badge/Node.js-v20+-green.svg)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg)](https://react.dev/)
[![Prisma](https://img.shields.io/badge/Prisma-5.14+-2D3748.svg)](https://www.prisma.io/)
[![Chrome Extension](https://img.shields.io/badge/Manifest-V3-orange.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Tests](https://img.shields.io/badge/Tests-251%20Passing-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. Executive Summary

**PhishNetra** is a defense-in-depth cybersecurity intelligence platform engineered to replace legacy static URL blacklists with real-time, explainable, multi-signal phishing detection. It combines server-side deep multi-layer analysis, dedicated Python machine learning with explainable AI (SHAP), and an endpoint Manifest V3 browser extension with Adversary-in-the-Middle (AiTM) reverse proxy defenses.

### Key Capabilities
- **Multi-Layer Zero-Trust Risk Engine:** Synthesizes lexical heuristics, RDAP domain age, DNS infrastructure anomalies, TLS certificate validity, threat reputation feeds, and DOM page inspection into calibrated 0–100 risk scores.
- **Fail-Safe Scoring Architecture:** Deterministic bounds and NaN-resilience guarantees ensure compromised or corrupted layer telemetry never fails open.
- **SSRF Immunity:** Multi-layered IP address resolution filtering blocks attacks against loopback, RFC 1918 private subnets, link-local, carrier-grade NAT, and cloud metadata endpoints (`169.254.169.254`).
- **Endpoint Protection (Manifest V3 Extension):** Real-time tab scanning, AiTM reverse proxy interception, form action hijacking detection, and automated browser badge alerts.
- **Advanced Threat Operations:** Automated Threat Campaigns (STIX 2.1), TAXII 2.1 Threat Exchange, BGP Route Poisoning Radar, RBI Sandbox integration, Credential Tarpit poisoning, and FIDO2/WebAuthn anti-phishing posture verification.

---

## 2. System Architecture

```text
                               ┌──────────────────────────────────────────────┐
                               │       Client & Endpoint Applications         │
                               └──────────────────────┬───────────────────────┘
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       │                                                             │
                       ▼                                                             ▼
         ┌───────────────────────────┐                                 ┌───────────────────────────┐
         │  apps/web (SOC Dashboard) │                                 │ apps/extension (MV3 Ext)  │
         │   React 18 + Vite + TS    │                                 │ Real-Time DOM & AiTM Guard│
         └─────────────┬─────────────┘                                 └─────────────┬─────────────┘
                       │                                                             │
                       └──────────────────────────────┬──────────────────────────────┘
                                                      │ (HTTP/REST + Bearer / API Key)
                                                      ▼
                                       ┌─────────────────────────────┐
                                       │   apps/api (Backend Core)   │
                                       │    Express + TS + Zod       │
                                       └──────────────┬──────────────┘
                                                      │
         ┌────────────────────────────────────────────┼────────────────────────────────────────────┐
         ▼                                            ▼                                            ▼
┌──────────────────────────┐             ┌──────────────────────────┐                 ┌──────────────────────────┐
│ services/ml (FastAPI)    │             │ PostgreSQL & Prisma ORM  │                 │ Dual Cache Layer         │
│ • Random Forest (sub-5ms)│             │ • Users & RBAC Roles     │                 │ • In-Memory LRU Cache    │
│ • 18+ Lexical Features   │             │ • Scans, Dossiers, Queue │                 │ • Redis Distributed      │
│ • SHAP Feature Attrib.   │             │ • Threat Intelligence    │                 │   (with offline fallback)│
└──────────────────────────┘             └──────────────────────────┘                 └──────────────────────────┘
```

---

## 3. Repository Directory Structure

```text
PhishNetra/
│
├── apps/
│   ├── api/                     # Node.js + Express + TypeScript Backend Core
│   │   ├── src/controllers/     # REST Controllers (Analysis, Auth, AiTM, CTI, Queue, etc.)
│   │   ├── src/services/        # Business Logic & Multi-Layer Risk Engine
│   │   │   └── analysis/        # DNS, TLS, RDAP, Reputation, IP SSRF utilities
│   │   └── tests/               # 182 comprehensive Jest + Supertest suites
│   │
│   ├── web/                     # React 18 + Vite SOC Analyst Dashboard
│   │   ├── src/pages/           # Live Scan, Batch Queue, Domains, Reports, Settings, etc.
│   │   └── src/components/      # SOC Telemetry, Threat Gauge, Risk Matrices
│   │
│   └── extension/               # Chrome Manifest V3 Browser Extension
│       ├── src/background/      # Service worker, AiTM detector, badge manager
│       ├── src/content/         # Content script DOM scanner & credential form monitor
│       └── src/popup/           # Extension status UI & telemetry viewer
│
├── services/
│   └── ml/                      # Python 3.10 + FastAPI Machine Learning Microservice
│       ├── app/                 # Feature extraction, inference, drift & SHAP explainability
│       ├── training/            # Model training & synthetic data generation pipelines
│       ├── artifacts/           # Serialized Random Forest models & performance metrics
│       └── tests/               # 58 Pytest automated ML & SSRF test cases
│
├── packages/
│   └── shared/                  # Shared TypeScript types, Zod schemas, & constants
│
├── docs/                        # Complete technical documentation & Architecture Decision Records
│   ├── ARCHITECTURE.md          # Full deep-dive system architecture
│   ├── IMPLEMENTATION_STATUS.md # Complete 20-milestone delivery status log
│   ├── EXTENSION.md             # Browser extension design & threat protection
│   ├── SECURITY.md              # Zero-Trust guidelines & vulnerability controls
│   └── API.md                   # REST API endpoint reference
│
├── markdowns/                   # Project reference guides & interview briefs
│   ├── 01_REFERENCE_ANALYSIS.md # Technical baseline architecture analysis
│   ├── 02_AI_IDE_MASTER_PROMPT.md # Engineering prompts & specification catalog
│   └── 03_RESUME_AND_INTERVIEW.md # Architecture talking points & engineering notes
│
├── prisma/
│   └── schema.prisma            # Database schema (Users, Analyses, Evidence, Queue)
│
├── docker-compose.yml           # Multi-container orchestration (API, Web, ML, DB, Redis)
└── package.json                 # Monorepo workspaces & scripts
```

---

## 4. Quickstart Guide

### Prerequisites
- **Node.js**: `v18.0.0` or higher (`v20+` recommended)
- **npm**: `v9.0.0` or higher
- **Python**: `v3.10.0` or higher
- **Docker** (optional, for PostgreSQL and Redis services)

### Step 1: Install Dependencies
```bash
# Install Node.js monorepo workspace dependencies
npm install

# Install Python ML microservice dependencies
pip install -r services/ml/requirements.txt
```

### Step 2: Configure Environment
```bash
cp .env.example .env
```

### Step 3: Initialize Database & Build Shared Packages
```bash
# Build shared TypeScript schemas
npm run build:shared

# Generate Prisma client
npx prisma generate --schema=prisma/schema.prisma
```

---

## 5. Running the Application

You can start each service individually or run them concurrently:

| Service | Port | Command | Description |
| :--- | :--- | :--- | :--- |
| **API Server** | `5000` | `npm run dev:api` | REST endpoints at `http://localhost:5000/api` |
| **SOC Web Dashboard** | `5173` | `npm run dev:web` | Browser UI at `http://localhost:5173` |
| **ML Microservice** | `8000` | `npm run dev:ml` | FastAPI docs at `http://127.0.0.1:8000/docs` |
| **Browser Extension** | — | `npm run dev:extension` | Manifest V3 build outputs to `apps/extension/dist` |

### Sideloading the Browser Extension (Chrome / Edge / Brave):
1. Run `npm run build:extension` (or `npm run dev:extension` for live reload).
2. Open your browser and navigate to `chrome://extensions/`.
3. Enable **Developer mode** (top right toggle).
4. Click **Load unpacked** and select the directory: `PhishNetra/apps/extension/dist`.
5. The PhishNetra shield icon will appear in your toolbar with live protection active.

---

## 6. Testing & Quality Assurance

The codebase includes comprehensive automated test suites covering all layers, contracts, and threat models:

```bash
# Run all automated tests across all stacks (Node.js + Python ML)
npm run test:all

# Run backend API test suites (182 tests)
npm run test:api

# Run browser extension test suites (12 tests)
npm run test:extension

# Run Python ML test suites (58 tests)
npm run test:ml
```

### Current Test Suite Status
- **Backend API Tests:** `182 / 182 PASSED` (27 test suites)
- **Extension Tests:** `12 / 12 PASSED` (2 test suites)
- **Python ML Tests:** `58 / 58 PASSED` (8 test suites)
- **Total:** `252 Automated Tests Passing (100% Pass Rate)`

---

## 7. Zero-Trust Security Architecture

PhishNetra enforces rigorous Zero-Trust controls at every tier:

1. **SSRF Immunity:**
   - Pre-resolution and post-resolution IP filtering rejects loopback (`127.0.0.0/8`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and carrier-grade NAT (`100.64.0.0/10`).
   - Cloud instance metadata services (AWS/GCP/Azure `169.254.169.254`) are systematically denied and flagged as critical threats.
2. **Fail-Safe Scoring Guarantees:**
   - Multi-layer composite calculations reject `NaN` or infinite values to ensure poisoned or malformed layer results never default to a `SAFE` verdict.
3. **Authentication & Access Boundaries:**
   - Dual-mode authentication supports standard JWT Bearer tokens (with case-insensitive parsing) and cryptographically secure API keys (`x-api-key`).
   - Query pagination parameters and string inputs are strictly bounded using Zod schemas to prevent memory exhaustion.
4. **Adversary-in-the-Middle (AiTM) Detection:**
   - Real-time detection of reverse proxy intermediate hops, TLS SNI mismatches, and credential action hijacking.

---

## 8. Milestone Matrix & Documentation Map

| Milestone | Capability / Feature | Documentation |
| :--- | :--- | :--- |
| **M1–M3** | Core Multi-Layer Risk Engine, DNS/TLS/RDAP, DOM Analysis | [ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| **M4** | Worker Queue, Typosquatting Engine, Caching & Dossier Hub | [IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) |
| **M5–M7** | MLOps Lifecycle, SHAP Explainability, Drift Detection | [MLOPS.md](docs/MLOPS.md) |
| **M8–M10** | Red Team Threat Simulation, Automated Vector Benchmarks | [THREAT_SIMULATION.md](docs/THREAT_SIMULATION.md) |
| **M11–M14** | Chrome MV3 Extension, Real-Time DOM & Credential Interception | [EXTENSION.md](docs/EXTENSION.md) |
| **M15** | Remote Browser Isolation (RBI) Sandbox & Phishing Tarpit | [RBI_SANDBOX_AND_TARPIT.md](docs/RBI_SANDBOX_AND_TARPIT.md) |
| **M16** | AiTM Reverse Proxy Defense, CTI Fusion, SOC2/NIST Audits | [AITM_AND_INTEL_FUSION.md](docs/AITM_AND_INTEL_FUSION.md) |
| **M17–M19** | GenAI Steganography Defense, Telecom Spoofing, Digital Forensics | [GENAI_DEFENSE_AND_DIGITAL_FORENSICS.md](docs/GENAI_DEFENSE_AND_DIGITAL_FORENSICS.md) |
| **M20** | CTI TAXII 2.1 Exchange, BGP Route Radar, FIDO2/WebAuthn Guard | [CTI_BGP_AND_FIDO2_GUARD.md](docs/CTI_BGP_AND_FIDO2_GUARD.md) |

---

## 9. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
