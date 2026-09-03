# PhishNetra — System Architecture (Milestone 1)

**Framework Title:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Version:** Milestone 1.0 (Month 1 → Month 1.5 Prototype)

---

## 1. High-Level Architectural Model

PhishNetra Milestone 1 implements a modular, service-oriented monorepo architecture engineered to isolate application lifecycle management from machine learning feature computation and inference.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            PRESENTATION LAYER                                │
│                                                                             │
│                  React 18 + Vite + Tailwind CSS (apps/web)                  │
│   • SOC Threat Dashboard      • Live URL Scanner      • Report Inspector     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP / JSON (JWT Auth)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            APPLICATION API LAYER                            │
│                                                                             │
│                    Node.js + Express + TypeScript (apps/api)                │
│   • Request Validation (Zod)  • JWT Auth Service      • URL Normalizer      │
│   • Composite Risk Engine     • Rate Limiter          • Error Boundary      │
└──────────────────────┬───────────────────────────────┬──────────────────────┘
                       │                               │
            Prisma ORM │                    HTTP / JSON│
                       ▼                               ▼
┌──────────────────────────────┐  ┌───────────────────────────────────────────┐
│       DATABASE LAYER         │  │            ML MICROSERVICE LAYER          │
│                              │  │                                           │
│   PostgreSQL (prisma/)       │  │   Python 3.10 + FastAPI (services/ml)     │
│   • users table              │  │   • URL Normalizer & Canonicalizer        │
│   • analyses table           │  │   • 18+ Deterministic URL Feature Engine  │
│   • analysis_evidence table  │  │   • Random Forest Baseline Classifier     │
│                              │  │   • Serialized Artifact (baseline_model)  │
└──────────────────────────────┘  └───────────────────────────────────────────┘
```

---

## 2. Core Service Boundaries

### 2.1 React Frontend Application (`apps/web`)
- **Role:** Security Operations Center (SOC) style analyst web interface.
- **Key Responsibilities:**
  - Secure authentication & session token lifecycle management.
  - Interactive live URL threat submission.
  - Visualization of calibrated risk scores (0–100 gauge), confidence ratings, and verdict badges.
  - Tabular breakdown of triggered heuristic evidence and extracted feature vectors.
  - Historical telemetry audit feed for authenticated security analysts.

### 2.2 Node.js REST API Server (`apps/api`)
- **Role:** Central application gateway and risk orchestration engine.
- **Key Responsibilities:**
  - Credential hashing (bcrypt) and JWT signing/verification.
  - Strict input validation using Zod schemas (`@phishnetra/shared`).
  - URL scheme, hostname, and port canonicalization.
  - Orchestration of ML microservice calls with deterministic offline fallbacks.
  - Synthesis of composite risk scores via `RiskEngine` (60% ML weight + 40% rule evidence weight).
  - PostgreSQL persistence with relational foreign keys (`User` -> `Analysis` -> `AnalysisEvidence`).

### 2.3 Python ML Microservice (`services/ml`)
- **Role:** High-throughput feature engineering and baseline model inference engine.
- **Key Responsibilities:**
  - High-performance deterministic lexical and structural URL feature extraction (18+ features).
  - Shannon character entropy computation and IPv4/IPv6 pattern evaluation.
  - Real-time classification via serialized scikit-learn `RandomForestClassifier`.
  - Export of feature contribution vectors and health telemetry (`/health`, `/docs`).

### 2.4 Shared Contract Package (`packages/shared`)
- **Role:** Single source of truth for types and data validation.
- **Key Responsibilities:**
  - Exports Zod validation schemas for `AnalysisRequest`, `AnalysisResponse`, `EvidenceItem`, `URLFeatureVector`, and Auth DTOs.
  - Prevents contract divergence between API and Web clients.

---

## 3. Threat Analysis Data Flow

```text
1. User enters URL in Web UI
   │
2. POST /api/analyze (Bearer JWT)
   │
3. Express API validates URL via Zod & normalizes structure
   │
4. API dispatches normalized URL to Python ML microservice (POST /api/v1/predict)
   │
5. Python ML Service:
   ├── Extracts 18+ deterministic lexical & syntactic features
   ├── Converts features to ordered vector
   └── Generates probability via RandomForestClassifier
   │
6. API Risk Engine:
   ├── Combines ML probability (60%) + Rule heuristics (40%)
   ├── Maps composite score to Verdict (SAFE, SUSPICIOUS, PHISHING)
   └── Compiles explainable EvidenceItem array with severity tags
   │
7. Prisma persists Analysis & Evidence records in PostgreSQL
   │
8. JSON response returned to Web UI -> Rendered on Deep-Dive Report Page
```

---

## 4. Database Entity Relationships

```text
┌─────────────────────────┐
│          User           │
├─────────────────────────┤
│ id: String (UUID, PK)   │
│ email: String (Unique)  │
│ name: String            │
│ passwordHash: String    │
│ role: String            │
│ createdAt: DateTime     │
└────────────┬────────────┘
             │ 1
             │
             │ has many
             │
             │ *
┌────────────▼────────────┐       1       * ┌─────────────────────────┐
│        Analysis         ├─────────────────┤    AnalysisEvidence     │
├─────────────────────────┤                 ├─────────────────────────┤
│ id: String (UUID, PK)   │                 │ id: String (UUID, PK)   │
│ userId: String (FK)     │                 │ analysisId: String (FK) │
│ url: String             │                 │ featureKey: String      │
│ normalizedUrl: String   │                 │ featureValue: String    │
│ verdict: String         │                 │ severity: String        │
│ riskScore: Float        │                 │ description: String     │
│ riskLevel: String       │                 │ contribution: Float     │
│ confidence: Float       │                 │ createdAt: DateTime     │
│ mlProbability: Float    │                 └─────────────────────────┘
│ status: String          │
│ createdAt: DateTime     │
└─────────────────────────┘
```

---

## 5. Security Isolation & SSRF Boundary

In Milestone 1, **all analysis operates strictly on offline URL syntax and lexical tokens**. No server-side HTTP GET requests or DOM scrapers are executed against arbitrary user targets. This deliberate architectural decision guarantees immunity against Server-Side Request Forgery (SSRF) and cloud metadata exfiltration until an isolated, sandboxed analyzer environment is deployed in Milestone 3.
