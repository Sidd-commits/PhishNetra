# PhishNetra 🛡️

> **A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation**

[![Node.js](https://img.shields.io/badge/Node.js-v20+-green.svg)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg)](https://react.dev/)
[![Prisma](https://img.shields.io/badge/Prisma-5.14+-2D3748.svg)](https://www.prisma.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. Executive Summary

PhishNetra is an end-to-end cybersecurity threat intelligence platform designed to replace legacy blacklists with real-time, explainable, multi-signal phishing detection. 

This repository contains the **Milestone 1 working prototype (Month 1 → Month 1.5)**, establishing the core monorepo architecture, deterministic URL feature extraction engine, baseline machine learning classifier, composite risk scoring engine, PostgreSQL persistence layer, and React SOC analyst dashboard.

---

## 2. System Architecture (Milestone 1)

```text
                    PHISHNETRA (Monorepo)
                              │
                              ▼
                 React Frontend (apps/web)
                   [Vite + TS + Tailwind]
                              │
                              ▼ (HTTP / REST + JWT)
                              │
                 Node.js REST API (apps/api)
                   [Express + TS + Zod]
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
       PostgreSQL Database               ML Service (services/ml)
        [Prisma ORM]                      [FastAPI + Python]
              │                               │
              │                               ▼
              │                   Deterministic URL Features
              │                               │
              │                               ▼
              │                   Baseline ML Model (RF)
              │                               │
              └───────────────┬───────────────┘
                              ▼
                         Risk Engine
                   [ML Score + Rule Evidence]
                              │
                              ▼
                        Stored Analysis
                              │
                              ▼
                       Frontend Result
```

---

## 3. Directory Structure

```text
PhishNetra/
│
├── apps/
│   ├── web/                     # React 18 + Vite + Tailwind CSS Frontend
│   └── api/                     # Node.js + Express + TypeScript REST API
│
├── services/
│   └── ml/                      # Python 3.10 + FastAPI ML Microservice
│       ├── app/                 # Feature extraction & inference routers
│       ├── data/                # Dataset guidelines & synthetic fixtures
│       ├── training/            # Model training and evaluation scripts
│       └── artifacts/           # Serialized baseline model & metrics
│
├── packages/
│   └── shared/                  # Shared TypeScript types & Zod schemas
│
├── prisma/
│   └── schema.prisma            # PostgreSQL schema (User, Analysis, Evidence)
│
├── docs/                        # Complete technical documentation
│   ├── IMPLEMENTATION_STATUS.md
│   ├── ARCHITECTURE.md
│   ├── API.md
│   ├── ML_METHODOLOGY.md
│   ├── SECURITY.md
│   └── ROADMAP.md
│
├── tests/                       # Automated test suites
├── docker-compose.yml           # Local multi-container development environment
├── .env.example                 # Root environment configuration template
└── package.json                 # Monorepo root workspace configuration
```

---

## 4. Prerequisites

Before running PhishNetra locally, ensure you have:

- **Node.js**: v18.0.0 or higher (v20+ recommended)
- **npm**: v9.0.0 or higher
- **Python**: v3.10.0 or higher
- **PostgreSQL** or **Docker** (optional for containerized PostgreSQL)

---

## 5. Quickstart Guide

### Step 1: Clone and Configure Environment

```bash
# Clone the repository
git clone https://github.com/your-org/PhishNetra.git
cd PhishNetra

# Copy environment template
cp .env.example .env
```

### Step 2: Install Dependencies

```bash
# Install Node.js monorepo dependencies
npm install

# Install Python ML dependencies
pip install -r services/ml/requirements.txt
```

### Step 3: Train Baseline ML Model & Generate Artifacts

```bash
python services/ml/training/train.py
```

### Step 4: Setup Database (Prisma)

```bash
# Generate Prisma client
npx prisma generate --schema=prisma/schema.prisma

# (Optional) If PostgreSQL is running locally, push the schema:
# npx prisma db push --schema=prisma/schema.prisma
```

---

## 6. Running the Services

You can start the components concurrently in separate terminals:

### 1. Start Python ML Microservice (Port 8000)
```bash
cd services/ml
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
*API docs available at: `http://localhost:8000/docs`*

### 2. Start Node.js API Server (Port 5000)
```bash
npm run dev:api
```
*REST endpoints available at: `http://localhost:5000/api`*

### 3. Start React Web Dashboard (Port 5173)
```bash
npm run dev:web
```
*Open your browser at: `http://localhost:5173`*

---

## 7. Running Automated Test Suites

### Backend API Tests (Jest & Supertest)
```bash
npm run test:api
```

### Python ML & Feature Extractor Tests (Pytest)
```bash
cd services/ml
pytest -v
```

---

## 8. Milestone 1 Key Features

- **Analyst Authentication:** Secure register/login flow with bcrypt password hashing and JWT sessions.
- **Deterministic Feature Extractor:** 18+ lexical, statistical (Shannon entropy), and structural URL signals.
- **Baseline Machine Learning:** Serialized Random Forest model delivering sub-5ms inference latency.
- **Calibrated Risk Engine:** Synthesizes ML probabilities (60%) and deterministic security rules (40%) into an explainable 0–100 risk score.
- **SOC Analyst Console:** Threat gauge, rule evidence table, and telemetry history feed.
- **SSRF Immunity:** Static URL lexical analysis with active server-side HTTP fetching intentionally restricted.

---

## 9. Documentation

For in-depth specifications, consult the `/docs` directory:

- [Implementation Status](docs/IMPLEMENTATION_STATUS.md)
- [System Architecture](docs/ARCHITECTURE.md)
- [API Specification](docs/API.md)
- [ML Methodology](docs/ML_METHODOLOGY.md)
- [Security & Zero-Trust Policy](docs/SECURITY.md)
- [10-Month Master Roadmap](docs/ROADMAP.md)

---

## 10. License

MIT License. Developed as part of the PhishNetra Zero-Trust Threat Mitigation Framework.
