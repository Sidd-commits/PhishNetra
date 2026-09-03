# AI-FIRST IDE MASTER IMPLEMENTATION PROMPT — SENTINELSCOPE

## Role

You are the lead software architect and implementation agent for a production-quality student major project called **PhishNetra**.

The goal is NOT to clone an existing repository. Use the reference concept as inspiration and implement an original, significantly more advanced cybersecurity platform.

Reference concept:
- full-stack phishing detection platform
- machine-learning URL analysis
- Chrome extension
- reporting/reputation
- dashboard

Your implementation must be original in source code, UI, architecture and data model.

---

# 1. Product Goal

Build:

> PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation

The platform analyzes URLs/domains/webpages and produces:

- verdict
- calibrated risk score
- confidence
- evidence
- feature contributions
- domain intelligence
- reputation signals
- brand impersonation detection
- redirect information
- historical/community reports

It must have:

1. Web analyst dashboard
2. URL analysis API
3. ML inference service
4. secure analysis workers
5. PostgreSQL persistence
6. Redis job queue/cache
7. Chrome Manifest V3 extension
8. explainable AI
9. community reporting
10. RBAC
11. model evaluation
12. MLOps-ready structure

---

# 2. Mandatory Architecture

Use a monorepo:

```text
phishnetra/
├── apps/
│   ├── web/
│   ├── api/
│   └── extension/
├── services/
│   ├── ml/
│   └── analyzer/
├── packages/
│   ├── shared/
│   ├── schemas/
│   └── ui/
├── ml/
│   ├── data/
│   ├── features/
│   ├── training/
│   ├── evaluation/
│   └── models/
├── infra/
│   ├── docker/
│   └── monitoring/
├── docs/
├── tests/
├── docker-compose.yml
├── .env.example
└── README.md
```

Preferred stack:

- React + TypeScript + Vite
- Tailwind
- Node.js + TypeScript
- Express
- PostgreSQL
- Prisma
- Redis
- BullMQ
- Python + FastAPI
- scikit-learn
- XGBoost/LightGBM where appropriate
- SHAP
- Docker
- GitHub Actions

---

# 3. Development Rules

Do NOT:

- put all backend logic into one file
- put ML logic into the Node server
- hardcode API keys
- hardcode localhost URLs
- silently redirect users
- fabricate confidence scores
- invent security evidence
- disable TLS verification
- fetch arbitrary user URLs without SSRF controls
- use broad `except:` blocks in Python
- trust user reports as ground truth
- claim ML accuracy without measured experiments

Do:

- use environment variables
- validate every external input
- create typed interfaces
- create unit tests
- create integration tests
- use structured logging
- use consistent error schemas
- version the model
- version the analysis schema
- write documentation while implementing

---

# 4. First Implementation Order

Implement in this exact order.

## Step 1

Create repository structure.

## Step 2

Create shared schemas.

Define:

```text
AnalysisRequest
AnalysisResponse
EvidenceItem
DomainIntel
ReputationSignal
ThreatVerdict
Report
User
BatchJob
```

Use Zod for TypeScript validation and Pydantic for Python.

## Step 3

Implement PostgreSQL + Prisma.

Create tables for:

- users
- roles
- sessions
- analyses
- evidence
- domains
- domain_reports
- brands
- batch_jobs
- batch_items
- model_versions
- audit_logs

## Step 4

Implement authentication.

Requirements:

- register
- login
- logout
- refresh
- password hashing
- httpOnly cookies
- secure production cookie configuration
- role middleware
- rate limiting
- validation

## Step 5

Implement URL canonicalization.

Normalize:

- scheme
- hostname
- default ports
- trailing slash
- Unicode/IDN handling
- percent encoding

Store original and canonical URL.

## Step 6

Implement deterministic feature extraction.

Create independent feature modules:

```text
url/
domain/
dns/
tls/
html/
brand/
reputation/
```

Every extractor must return:

```typescript
{
  key,
  value,
  score,
  confidence,
  evidence
}
```

## Step 7

Implement SSRF-safe fetching.

The analyzer must:

- accept only http/https
- reject localhost
- reject private IP ranges
- reject link-local
- reject loopback
- reject cloud metadata endpoints
- limit redirects
- resolve and validate destination IPs
- enforce timeout
- limit response size
- identify unsupported content types
- isolate fetching from the API process

Add tests specifically for SSRF bypass classes.

## Step 8

Implement ML baseline.

Start with:

- Logistic Regression
- Random Forest
- Gradient Boosting

Evaluate all.

Then test XGBoost/LightGBM if available.

Do not assume the most complex model is best.

## Step 9

Implement explainability.

Use SHAP where supported.

Store:

```text
feature
value
contribution
direction
humanExplanation
```

## Step 10

Implement risk engine.

Every signal must be normalized to `[0,1]`.

Initial weights may be:

```text
ML             0.45
Reputation     0.20
Domain         0.15
Content        0.10
Brand          0.10
```

Treat these as configuration, not scientific truth.

Make them easy to change.

## Step 11

Implement async jobs.

Use:

```text
API
 ↓
Redis
 ↓
BullMQ
 ↓
Analyzer Worker
 ↓
ML Worker
 ↓
Result Aggregator
```

Support:

```text
QUEUED
RUNNING
COMPLETED
FAILED
```

## Step 12

Implement React dashboard.

Pages:

```text
/login
/dashboard
/analyze
/analysis/:id
/domains/:domain
/reports
/reports/:id
/batch
/models
/settings
```

## Step 13

Implement investigation UX.

For each analysis show:

1. verdict
2. score
3. confidence
4. top evidence
5. URL signals
6. domain signals
7. DNS
8. TLS
9. page signals
10. reputation
11. brand impersonation
12. community reports
13. related indicators

## Step 14

Implement extension.

Features:

- active URL detection
- API call
- risk badge
- popup
- warning interstitial
- open investigation page

Never silently redirect.

## Step 15

Implement reporting.

Reports must have moderation state.

Do not immediately convert a report into ground truth.

## Step 16

Implement typosquatting.

Use:

- edit distance
- Unicode normalization
- punycode detection
- homoglyph analysis
- brand database

## Step 17

Implement model evaluation dashboard.

Show:

- accuracy
- precision
- recall
- F1
- ROC-AUC
- PR-AUC
- confusion matrix
- false-positive rate
- false-negative rate
- inference latency

## Step 18

Implement adversarial benchmark.

Use safe synthetic transformations:

- encoding
- case changes
- subdomain insertion
- domain mutation
- query manipulation
- punycode
- path manipulation

Do not create live phishing infrastructure.

## Step 19

Implement MLOps.

Add:

- MLflow
- DVC
- model versioning
- GitHub Actions
- reproducible training
- evaluation gate

CI should fail if a new model is worse than the selected baseline beyond configured tolerances.

## Step 20

Implement observability.

Add:

- request ID
- analysis ID
- structured logs
- `/health`
- `/ready`
- metrics
- latency measurement

---

# 5. UI Requirements

Design should look like a serious cybersecurity product.

Avoid:

- generic gradient landing pages
- excessive animations
- cartoon security imagery
- fake statistics
- meaningless glassmorphism

Use:

- dense but readable analyst layouts
- clear severity states
- tables
- evidence cards
- timeline views
- threat graphs
- charts
- responsive layout
- accessible components

Primary UI concept:

```text
SECURITY ANALYSIS

example.com

LOW RISK
14 / 100

Why?
✓ Long-established domain
✓ Valid certificate
✓ No known reputation hits

Potential concerns
! 2 external script origins
```

---

# 6. API Requirements

Every API response must use consistent structures.

Success:

```json
{
  "success": true,
  "data": {}
}
```

Error:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid URL"
  },
  "requestId": "..."
}
```

Never return stack traces to clients.

---

# 7. Testing Requirements

Minimum:

### Unit

- URL canonicalization
- feature extractors
- risk normalization
- score aggregation
- brand matching

### Integration

- auth
- analysis creation
- analysis retrieval
- reports
- database

### Security

- SSRF
- auth bypass
- RBAC bypass
- rate limiting
- malformed URLs
- oversized payloads

### ML

- deterministic inference
- feature schema compatibility
- model version compatibility

---

# 8. Documentation Requirements

Generate:

```text
docs/
├── ARCHITECTURE.md
├── API.md
├── SECURITY.md
├── THREAT_MODEL.md
├── ML_METHODOLOGY.md
├── DATASET.md
├── MODEL_CARD.md
├── EXTENSION.md
├── DEPLOYMENT.md
└── ADR/
```

Each important architectural decision should have an ADR.

---

# 9. AI Agent Behaviour

Before implementing a major subsystem:

1. inspect current repository
2. understand existing code
3. avoid unnecessary rewrites
4. update architecture documentation
5. implement incrementally
6. run tests
7. fix errors
8. update README
9. summarize changed files
10. state remaining limitations

Do not silently replace working architecture.

---

# 10. Completion Criteria

The project should eventually demonstrate:

```text
URL
 ↓
Canonicalization
 ↓
Fast lexical analysis
 ↓
Async deep analysis
 ↓
Domain/DNS/TLS intelligence
 ↓
Safe page analysis
 ↓
ML ensemble
 ↓
Reputation
 ↓
Brand impersonation
 ↓
Risk engine
 ↓
SHAP evidence
 ↓
Grounded explanation
 ↓
Database
 ↓
Dashboard
 ↓
Browser extension
```

The final result must be something that can be explained in a technical interview from:

- frontend
- backend
- database
- distributed processing
- cybersecurity
- ML
- explainability
- MLOps
- browser extension
- security architecture

perspectives.
