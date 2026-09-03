# PhishNetra Reference Analysis & Reconstruction Blueprint

## 0. Purpose

This document reverse-engineers the public repository `Sarahkhan20/PhishNet` at a system-design level and converts its ideas into a cleaner, production-oriented specification for a new major project.

Reference repository:
https://github.com/Sarahkhan20/PhishNet

Important: this is a **rebuild specification**, not a request to copy source code verbatim. The new project should use the reference project's product ideas while implementing a substantially different, modern architecture and original UI/code.

---

# 1. Executive Summary

The reference PhishNet is a web platform + Chrome extension for phishing/unsafe-URL detection.

Its central workflow is:

1. User enters or encounters a URL.
2. A Flask ML service extracts URL/domain/page-level signals.
3. A serialized Gradient Boosting model is used for classification.
4. A separate heuristic/feature-count endpoint exposes interpretable triggers.
5. A React frontend displays analysis/results.
6. A Node/Express backend manages application concerns such as:
   - authentication
   - MongoDB persistence
   - reports
   - domain/report records
   - contacts
   - premium payments
   - user/admin state
7. A Chrome extension obtains the active tab URL and calls the Flask analysis endpoint.

The repository therefore combines **cybersecurity + classical machine learning + full-stack web development + browser-extension development + payments + community reporting**.

The most important opportunity is to turn this from a student-style URL classifier into an **AI-assisted, explainable, multi-signal threat-intelligence platform**.

---

# 2. Reference Repository Structure

Observed top-level structure:

```text
PhishNet/
├── FlaskBack/
├── automate/
├── backend/
├── chrome_extension/
├── frontend/
└── README.md
```

### Backend

```text
backend/
├── config/
├── controllers/
├── models/
├── routes/
├── utils/
├── package.json
└── server.js
```

The Node backend follows a recognizable MVC-ish Express structure.

Controllers observed include:

- Lawyer.js
- auth.js
- contact.js
- domainPage.js
- reportDomain.js
- user.js

Models include:

- DomainPage.js
- Lawyer.js
- User.js
- contact.js
- reportDomain.js

Routes include:

- auth.js
- users.js
- Lawyer.js
- contact.js
- payment.js
- domainPage.js
- reportDomain.js

### Frontend

```text
frontend/
└── src/
    ├── Components/
    │   ├── Footer/
    │   └── Navbar/
    ├── Pages/
    │   ├── Login/
    │   ├── allreports/
    │   ├── dashboard/
    │   ├── home/
    │   ├── payment/
    │   ├── report/
    │   └── result/
    ├── context/
    │   └── UserContext.js
    ├── App.js
    ├── App.css
    ├── index.css
    └── index.js
```

The React app uses React Router and a UserContext.

### ML service

```text
FlaskBack/
├── app.py
├── function_tick.py
├── gradient_boosting_model.pkl
└── requirements.txt
```

The ML layer is a Flask application with a serialized Gradient Boosting model and substantial handcrafted feature-extraction code.

### Browser extension

```text
chrome_extension/
├── index.html
├── logo.svg
├── manifest.json
└── script.js
```

The extension uses Manifest V3 and a service worker.

### Automation

```text
automate/
└── automateGmail.py
```

This suggests an automation direction around Gmail, although the reference repository's README does not document this subsystem deeply.

---

# 3. Technology Stack of the Reference

## Frontend

- React 18
- Create React App / react-scripts
- React Router DOM
- Axios
- Chart.js
- react-chartjs-2
- Recharts
- React Icons
- Font Awesome

The reference frontend's package file confirms React 18.2, Axios, Chart.js, Recharts and React Router DOM.

## Application backend

- Node.js
- Express
- MongoDB
- Mongoose
- JWT
- bcryptjs
- cookie-parser
- CORS
- Nodemailer
- Razorpay
- Cloudinary
- Multer
- dotenv
- Nodemon

## ML / analysis backend

- Python
- Flask
- Flask-CORS
- scikit-learn model artifact (`gradient_boosting_model.pkl`)
- BeautifulSoup
- requests
- python-whois
- tldextract
- socket
- urllib
- regex-based feature extraction

## Browser extension

- Chrome Extension Manifest V3
- service worker
- chrome.tabs
- chrome.scripting
- popup HTML/JS

---

# 4. Reference Runtime Architecture

```text
                         ┌──────────────────────┐
                         │       Browser        │
                         │   React Web Client   │
                         └──────────┬───────────┘
                                    │
                              HTTP / JSON
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Node / Express     │
                         │ Application Backend   │
                         ├──────────────────────┤
                         │ Auth                 │
                         │ Users                │
                         │ Reports              │
                         │ Payments             │
                         │ Domain records       │
                         └───────┬───────┬──────┘
                                 │       │
                              MongoDB   APIs

                         ┌──────────────────────┐
                         │     Flask ML API     │
                         ├──────────────────────┤
                         │ URL parsing          │
                         │ WHOIS                │
                         │ HTML analysis        │
                         │ 30-ish features      │
                         │ Gradient Boosting    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Gradient Boosting    │
                         │ serialized model     │
                         └──────────────────────┘

Chrome Extension
      │
      ├── gets active tab URL
      │
      └── POST /analyze_url ───────► Flask ML API
```

---

# 5. Reference Frontend Routing

The main React app defines routes approximately as:

```text
/login
/
/report
/dashboard
/getpremium
/results
/allreports
```

The application wraps the router in a UserProvider.

Conceptually:

```text
App
├── UserProvider
├── Navbar
├── Router
│   ├── Login
│   ├── Home
│   ├── Report
│   ├── Dashboard
│   ├── Premium
│   ├── Results
│   └── AllReports
└── Footer
```

This is a good basic separation but should be substantially improved for the new project.

---

# 6. Reference Node Backend

The Node server initializes:

- Express
- dotenv
- Mongoose
- cookie-parser
- CORS
- route modules

It connects to MongoDB through `MONGO_URL`.

Observed API prefixes:

```text
/api/auth
/api/users
/api/lawyer
/api/pay
/api/domainpage
/api/reportdomain
/api/contact
```

The server has a global error handler and listens on a configurable port.

### Authentication

The reference system:

- checks whether email already exists
- hashes passwords with bcrypt
- creates JWTs
- places the JWT in an access_token cookie
- verifies JWTs on user verification
- supports logout by expiring the cookie

The User schema contains:

```text
email
name
phone
password
isAdmin
isPremium
createdAt
updatedAt
```

### Important improvement

Do NOT reproduce the reference authentication implementation exactly.

Use:

- httpOnly cookies
- Secure cookies in production
- SameSite protection
- short-lived access tokens
- refresh-token rotation
- server-side authorization middleware
- rate limiting
- input validation
- password strength checks
- email verification
- optional OAuth
- audit logging

---

# 7. Reference Reporting System

A report contains:

```text
domainName
emailId
details
category
```

The reference exposes CRUD endpoints.

A separate DomainPage model stores:

```text
domainName
count
createdAt
updatedAt
```

The idea is that repeated reports increase a domain's report count.

When the count exceeds a threshold, the reference sends an email alert.

### Better version

Replace this with a proper threat-intelligence reputation model:

```text
Domain
├── canonicalDomain
├── registeredDomain
├── firstSeen
├── lastSeen
├── reportCount
├── confirmedMaliciousCount
├── confirmedSafeCount
├── reputationScore
├── confidence
├── status
├── sources[]
└── timestamps
```

Reports should become immutable security events rather than arbitrary CRUD records.

---

# 8. Reference Payment System

The reference integrates Razorpay.

Flow:

```text
Frontend
   │
   ├── request order
   ▼
Node backend
   │
   ├── create Razorpay order
   ▼
Frontend payment UI
   │
   ├── payment
   ▼
Node backend
   │
   ├── verify HMAC signature
   └── update isPremium
```

### Better version

Use subscription objects rather than a boolean:

```text
subscription
├── plan
├── provider
├── providerCustomerId
├── providerSubscriptionId
├── status
├── startDate
├── renewalDate
├── cancelAt
└── features
```

---

# 9. Reference ML System

This is the most important technical portion.

The Flask service performs feature extraction from a URL and sometimes from the target webpage.

The reference includes approximately 30 features.

Major feature families:

## URL lexical features

- IP address usage
- URL length
- URL shortening
- `@` symbol
- redirect markers
- prefix/suffix hyphen
- subdomain count
- HTTPS
- non-standard port
- URL depth

## Domain / registration features

- WHOIS registration period
- domain age
- DNS-related signals
- domain reputation-style heuristics

## HTML features

- favicon origin
- external resources
- anchor links
- script/link references
- form actions
- iframe usage
- popup behavior
- right-click disabling
- mouse-over behavior

## Reputation features

- website traffic/rank
- PageRank-style external lookup
- search-engine indexing
- hardcoded suspicious URL/IP lists

---

# 10. Reference Feature Representation

The model expects a vector where individual feature functions return values such as:

```text
1   = relatively legitimate
0   = uncertain / intermediate
-1  = suspicious
```

The feature vector is then passed into the Gradient Boosting model.

This is an important architectural idea: the model is not operating directly on raw HTML. It receives engineered security features.

---

# 11. Reference /analyze_url Flow

The Flask endpoint approximately performs:

```text
POST /analyze_url
        │
        ▼
Extract URL
        │
        ▼
Load gradient_boosting_model.pkl
        │
        ▼
FeatureExtraction(url)
        │
        ├── URL features
        ├── domain features
        ├── WHOIS
        ├── HTML
        ├── JavaScript patterns
        └── reputation checks
        │
        ▼
Feature vector
        │
        ├── count suspicious features
        │
        └── model.predict_proba()
        │
        ▼
Combine scores
        │
        ▼
Return verdict + scores
```

The reference combines a handcrafted suspicious-feature percentage with the model probability.

---

# 12. Critical Problems in the Reference ML Implementation

These problems should be treated as lessons rather than copied.

## 12.1 External page fetching is dangerous

The backend accepts a user-provided URL and performs server-side HTTP requests.

This creates SSRF risk.

A production system must:

- validate URL schemes
- reject localhost
- reject private IP ranges
- reject link-local addresses
- reject cloud metadata endpoints
- control redirects
- resolve DNS safely
- re-check resolved IPs after redirects
- enforce timeouts
- limit response sizes
- restrict ports
- isolate fetching from the main application

OWASP explicitly identifies SSRF as a risk when an application fetches attacker-controlled URLs.

## 12.2 Network calls are synchronous

WHOIS, HTTP requests, HTML parsing and external reputation calls can make a single analysis slow and fragile.

Use:

```text
API request
   │
   ▼
Job queue
   │
   ├── URL feature worker
   ├── DNS worker
   ├── WHOIS worker
   ├── reputation worker
   └── HTML worker
```

Then aggregate the results.

## 12.3 Feature extraction contains brittle logic

The reference code contains several signs of technical debt, including:

- broad `except:` blocks
- variables referenced inconsistently
- external services that can disappear
- hard-coded suspicious IPs
- obsolete reputation sources
- HTML regexes that are easy to bypass
- ambiguous feature semantics
- network operations inside model inference
- duplicated feature logic

The new project must use typed, testable feature extractors.

## 12.4 Score calculation must be mathematically correct

The reference mixes a percentage score with a probability in a way that risks scale mismatch.

For example:

```text
prediction_score = percentage
model_probability_score = probability
```

If one is in `[0,100]` and the other is in `[0,1]`, they cannot be combined directly without normalization.

New design:

```text
modelProbability = 0.0 ... 1.0

heuristicRisk = 0.0 ... 1.0

reputationRisk = 0.0 ... 1.0

threatScore =
    0.55 * modelProbability +
    0.25 * reputationRisk +
    0.20 * heuristicRisk
```

Weights should be learned or validated rather than arbitrary.

## 12.5 Do not generate fake confidence

A particularly important reference flaw is returning a random-looking model score rather than a genuine calibrated prediction.

The new project must NEVER fabricate security confidence.

Every displayed confidence must trace back to a reproducible computation.

---

# 13. Chrome Extension Analysis

The reference extension:

1. queries the active tab
2. reads the current URL
3. executes a script in the tab
4. calls the Flask API
5. sends the result to the popup
6. may redirect a user away based on a score threshold

Manifest V3 is used.

The permissions include:

```text
tabs
activeTab
scripting
```

### Problems

- hardcoded localhost API
- weak environment configuration
- overly aggressive redirect behavior
- no robust failure state
- no explicit user confirmation
- no secure production API configuration
- service-worker architecture is minimal
- no caching
- no analysis lifecycle state

### Better extension behavior

```text
Page opened
   │
   ▼
Extract URL
   │
   ▼
Fast local lexical pre-check
   │
   ▼
Backend threat analysis
   │
   ├── SAFE → unobtrusive badge
   │
   ├── SUSPICIOUS → warning panel
   │
   └── MALICIOUS → interstitial warning
                     │
                     ├── Go back
                     ├── View evidence
                     └── Continue anyway
```

Do not silently redirect users to another site.

---

# 14. New Project Vision

**Project Name:** PhishNetra  
**Official Project Title:** A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation

## Proposed name

### PhishNetra

Alternative names:

- PhishGuard AI
- ThreatLens
- URLSentinel
- NetShield AI
- PhishRadar
- LinkFortress
- PhishNetra

Recommended: **PhishNetra**

Tagline:

> Explainable, multi-signal phishing intelligence for the modern web.

---

# 15. New Product Definition

PhishNetra is an end-to-end cybersecurity platform that analyzes URLs, domains and webpages using multiple independent security signals and produces an explainable threat assessment.

The platform should combine:

```text
URL Intelligence
+
Domain Intelligence
+
DNS Intelligence
+
TLS Intelligence
+
HTML/DOM Analysis
+
Reputation Intelligence
+
ML Classification
+
LLM Explanation
+
Threat Graph
+
Community Reports
+
Browser Extension
+
Security Dashboard
+
Continuous Evaluation
```

This makes it significantly stronger than a simple phishing classifier.

---

# 16. Target Architecture

```text
                         ┌─────────────────────────┐
                         │       React / Web        │
                         │ Security Analyst Console │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │      API Gateway        │
                         │ Node.js / Express       │
                         └────────────┬────────────┘
                                      │
                ┌─────────────────────┼──────────────────────┐
                │                     │                      │
                ▼                     ▼                      ▼
       ┌────────────────┐   ┌────────────────┐    ┌─────────────────┐
       │ Analysis API   │   │ Auth / Users   │    │ Reports / TI    │
       └───────┬────────┘   └────────────────┘    └────────┬────────┘
               │                                           │
               ▼                                           ▼
       ┌────────────────┐                         ┌─────────────────┐
       │ Job Queue      │                         │ PostgreSQL       │
       │ Redis + Worker  │                         │ Primary DB       │
       └───────┬────────┘                         └─────────────────┘
               │
       ┌───────┼──────────────────────────────────────┐
       │       │                 │                     │
       ▼       ▼                 ▼                     ▼
   URL/DOM   DNS/TLS         Reputation             ML Service
   Worker    Worker          Worker                 FastAPI
       │       │                 │                     │
       └───────┴─────────────────┴─────────────────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │ Risk Engine  │
                       └──────┬───────┘
                              │
                  ┌───────────┼────────────┐
                  ▼           ▼            ▼
               Verdict     Evidence     Explanation
                              │
                              ▼
                     React / Extension
```

---

# 17. Recommended Modern Stack

## Frontend

Prefer:

- React + Vite
- TypeScript
- Tailwind CSS
- shadcn/ui or equivalent component system
- TanStack Query
- React Router
- Recharts
- Zod

## Backend

Use:

- Node.js
- TypeScript
- Express or NestJS
- Zod validation
- JWT + refresh-token architecture
- PostgreSQL
- Prisma

## ML service

Use:

- Python
- FastAPI
- scikit-learn
- XGBoost or LightGBM
- pandas
- numpy
- SHAP
- Pydantic

## Infrastructure

- Redis
- BullMQ / equivalent job queue
- Docker
- GitHub Actions
- Prometheus
- Grafana
- structured logging

## Browser extension

- Manifest V3
- TypeScript
- React for popup UI if desired
- service worker
- content scripts only when needed

---

# 18. Detection Engine Design

Do NOT depend on a single model.

Use an ensemble.

## Layer 1 — Deterministic URL analysis

Extract:

- URL length
- entropy
- number of subdomains
- unusual ports
- punycode
- percent encoding
- suspicious TLD
- IP-based host
- userinfo section
- excessive path depth
- suspicious query keys
- brand-like tokens
- homoglyph patterns
- shortening service
- redirect chains

## Layer 2 — Domain intelligence

Analyze:

- registration age
- expiration
- registrar
- nameservers
- DNS records
- ASN
- hosting provider
- country/region where available
- historical reputation
- domain similarity to protected brands

## Layer 3 — TLS

Extract:

- certificate validity
- issuer
- subject
- SANs
- certificate age
- hostname mismatch
- TLS errors
- certificate reuse indicators

Important:

> HTTPS does NOT mean a website is legitimate.

The new UI must teach this distinction.

## Layer 4 — Web content

Fetch safely inside an isolated worker.

Analyze:

- forms
- password fields
- external scripts
- iframes
- hidden elements
- suspicious redirects
- page title
- favicon
- brand impersonation
- external domains
- login/payment indicators

## Layer 5 — Reputation

Integrate multiple providers where licensing permits.

Possible enrichment providers include:

- VirusTotal
- Google Safe Browsing
- URLhaus
- PhishTank
- AbuseIPDB
- WHOIS/RDAP
- DNS providers

Do not assume public/free APIs are commercially usable. Respect each provider's terms and quotas.

---

# 19. ML Architecture

Train at least three models:

### Model A — URL classifier

Input:

- lexical URL features

Candidates:

- Logistic Regression
- Random Forest
- XGBoost

### Model B — Page classifier

Input:

- DOM/HTML features
- textual features

Candidates:

- gradient boosting
- transformer classifier if resources permit

### Model C — Ensemble

Combine:

```text
URL model
Domain reputation
Page model
External reputation
Heuristic engine
```

Output:

```json
{
  "verdict": "malicious",
  "score": 0.94,
  "confidence": 0.91,
  "risk_level": "critical"
}
```

---

# 20. Explainable AI

This is a major resume differentiator.

Use SHAP for model-level feature attribution.

Example:

```text
Threat Score: 94/100

Top contributing signals:

+ Domain registered 11 days ago
+ Host uses punycode
+ Login form posts to unrelated domain
+ 7 external script origins
+ Reputation provider reports malicious activity
+ URL contains encoded redirect parameter

Reducing risk:

- Valid TLS certificate
- Domain resolves consistently
```

The system should separate:

- evidence
- model contribution
- heuristic signals
- third-party reputation

Do not let an LLM invent evidence.

---

# 21. LLM Layer

The LLM should NOT be the primary detector.

Use it as an explanation/orchestration layer.

Input:

```json
{
  "verdict": "suspicious",
  "score": 0.86,
  "evidence": [...],
  "model_features": [...],
  "reputation": [...]
}
```

LLM output:

```text
This website is suspicious because...
```

Guardrails:

- LLM can only summarize supplied evidence.
- LLM cannot create new threat indicators.
- Output must be JSON-schema validated.
- Store model/provider/version metadata.
- Never send secrets.
- Avoid sending sensitive browsing data unnecessarily.

---

# 22. Brand Impersonation / Typosquatting Engine

The reference has a basic typosquatting idea.

Build a real engine.

Protected brand database:

```text
brand
├── canonicalDomain
├── aliases
├── logo hashes
├── known domains
└── sensitivity
```

Generate or detect:

- character substitution
- insertion
- deletion
- transposition
- homoglyphs
- hyphenation
- prefix/suffix
- lookalike TLDs
- punycode

Use edit distance + Unicode normalization + IDN analysis.

Example:

```text
paypal.com
paypa1.com
pay-pal.com
paypaI.com
paypal-secure.example
```

The UI should say:

> Possible impersonation of PayPal

rather than simply:

> Phishing.

---

# 23. Threat Graph

This is one of the strongest proposed additions.

Represent relationships:

```text
Domain
  │
  ├── resolves_to → IP
  ├── hosted_on → ASN
  ├── uses → Certificate
  ├── redirects_to → Domain
  ├── embeds → Script Domain
  ├── impersonates → Brand
  ├── reported_by → User
  └── associated_with → Threat Campaign
```

This creates a miniature threat-intelligence graph.

For a student project, PostgreSQL tables can model these relationships without introducing a graph database initially.

---

# 24. Community Reputation

Upgrade the reference reporting system.

Each report should contain:

```text
reportId
target
reporter
category
evidence
timestamp
status
reviewResult
```

Use weighted reputation:

```text
report reliability
+
historical reporter accuracy
+
number of independent reports
+
external reputation
+
ML score
```

Do not allow raw user reports to instantly mark a domain malicious.

Use moderation / verification states:

```text
UNVERIFIED
SUSPICIOUS
UNDER_REVIEW
CONFIRMED_MALICIOUS
CONFIRMED_SAFE
```

---

# 25. User Roles

Implement RBAC.

Roles:

```text
USER
RESEARCHER
MODERATOR
SECURITY_ANALYST
ADMIN
```

Capabilities:

### USER

- analyze URLs
- view own history
- submit reports

### RESEARCHER

- batch analysis
- export results
- access advanced evidence

### MODERATOR

- review reports
- resolve community reports

### SECURITY_ANALYST

- threat dashboard
- IOC investigation
- campaign correlation

### ADMIN

- users
- policies
- integrations
- system configuration

---

# 26. Security Dashboard

Dashboard should include:

```text
Total scans
Threats detected
False-positive rate
Detection rate
Recent threats
Top malicious TLDs
Top impersonated brands
Threat trends
Recent reports
Detection latency
Model version
```

Charts:

- threat volume over time
- safe vs suspicious vs malicious
- top threat categories
- domain age distribution
- score distribution
- model performance

---

# 27. Investigation Page

For one URL:

```text
URL
↓
Verdict
↓
Threat score
↓
Why?
↓
URL features
↓
Domain intelligence
↓
DNS
↓
TLS
↓
Page analysis
↓
External reputation
↓
Redirect chain
↓
Related domains
↓
Community reports
↓
Timeline
```

This should feel like a lightweight SOC analyst console.

---

# 28. Safe Preview

Do not simply fetch and display arbitrary HTML in the user's normal browser context.

Build a safe preview architecture.

Concept:

```text
Original URL
   │
   ▼
Isolated fetcher
   │
   ▼
Sanitized representation
   │
   ▼
Safe preview
```

Strip:

- scripts
- forms
- active navigation
- downloads
- dangerous embeds

This gives the project a strong security-engineering dimension.

---

# 29. Browser Extension — New Design

Extension UI:

```text
┌──────────────────────────────┐
│ PhishNetra                │
│                              │
│ ● LOW RISK                   │
│                              │
│ example.com                  │
│                              │
│ Risk 12 / 100                │
│                              │
│ ✓ Domain age: 8 years        │
│ ✓ TLS valid                  │
│ ✓ No reputation hits         │
│                              │
│ [View Analysis]              │
└──────────────────────────────┘
```

For threats:

```text
┌──────────────────────────────┐
│ ⚠ HIGH RISK                  │
│                              │
│ paypa1-login.example         │
│                              │
│ Risk 94 / 100                │
│                              │
│ Possible PayPal impersonation│
│ Domain registered 4 days ago │
│                              │
│ [Go Back] [Investigate]      │
└──────────────────────────────┘
```

Do not silently redirect.

---

# 30. Batch Analysis

Add a researcher mode.

Upload:

```text
CSV
TXT
JSON
```

Example:

```text
url
https://example.com
https://another-site.com
...
```

Pipeline:

```text
Upload
↓
Validate
↓
Queue jobs
↓
Workers
↓
Analyze
↓
Store
↓
Progress tracking
↓
Download CSV/JSON
```

This adds asynchronous processing and demonstrates real backend engineering.

---

# 31. Model Evaluation

Do not report only accuracy.

Report:

- precision
- recall
- F1
- ROC-AUC
- PR-AUC
- confusion matrix
- false-positive rate
- false-negative rate
- calibration
- inference latency

For cybersecurity, false negatives are particularly important.

Maintain separate validation datasets.

---

# 32. Adversarial Testing

Create an adversarial test suite.

Test transformations such as:

```text
URL encoding
case changes
subdomain insertion
homoglyphs
long query strings
redirect wrappers
shortened URLs
extra path segments
punycode
brand mutations
```

Measure whether the classifier remains robust.

Do not generate or distribute real credential-harvesting infrastructure. Use controlled test URLs/domains and synthetic fixtures.

---

# 33. Dataset Engineering

Create a reproducible data pipeline.

```text
Raw sources
   ↓
Deduplication
   ↓
Normalization
   ↓
Label validation
   ↓
Train / validation / test split
   ↓
Feature generation
   ↓
Dataset version
   ↓
Model training
   ↓
Evaluation
```

Avoid random row splitting when duplicates or campaigns can cross splits.

Prefer domain/time-aware splitting where appropriate to reduce leakage.

---

# 34. MLOps

This is a major improvement over the reference.

Implement:

```text
DVC
MLflow
GitHub Actions
Model Registry
Experiment tracking
```

Track:

```text
dataset version
feature version
model version
hyperparameters
metrics
training timestamp
code commit
```

Example:

```text
Model v1.3
Dataset v2.1
F1: 0.96
Recall: 0.98
Precision: 0.94
PR-AUC: 0.97
```

Only claim numbers actually measured by your implementation.

---

# 35. Caching

Analysis is expensive.

Use Redis.

Cache by:

```text
hash(canonicalURL)
```

Example:

```text
first request
    ↓
full analysis

same URL later
    ↓
cached result
```

Use TTLs because reputation changes.

---

# 36. Observability

Add:

- structured JSON logging
- request IDs
- analysis IDs
- latency metrics
- worker metrics
- error tracking
- health checks

Endpoints:

```text
GET /health
GET /ready
GET /metrics
```

---

# 37. API Design

Suggested API:

```text
POST   /api/v1/analysis
GET    /api/v1/analysis/:id
GET    /api/v1/analysis/:id/evidence

POST   /api/v1/reports
GET    /api/v1/reports
PATCH  /api/v1/reports/:id

GET    /api/v1/domains/:domain
GET    /api/v1/domains/:domain/history

POST   /api/v1/batch
GET    /api/v1/batch/:id

GET    /api/v1/dashboard/summary
GET    /api/v1/dashboard/trends

POST   /api/v1/auth/register
POST   /api/v1/auth/login
POST   /api/v1/auth/refresh
POST   /api/v1/auth/logout
```

Use OpenAPI documentation.

---

# 38. Database Design

Recommended PostgreSQL schema:

```text
users
sessions
roles
user_roles

analyses
analysis_features
analysis_evidence
analysis_reputation

domains
domain_events
domain_reports

ips
certificates
dns_records

brands
brand_domains

threat_campaigns
campaign_indicators

batch_jobs
batch_items

model_versions
feedback
audit_logs
```

---

# 39. Core Analysis Data Model

Example:

```json
{
  "analysisId": "uuid",
  "url": "https://example.com",
  "canonicalUrl": "https://example.com/",
  "domain": "example.com",
  "verdict": "suspicious",
  "riskScore": 82,
  "confidence": 0.91,
  "modelVersion": "url-xgb-1.2",
  "evidence": [
    {
      "type": "domain_age",
      "severity": "high",
      "value": 8,
      "explanation": "Domain is newly registered"
    }
  ],
  "timestamps": {
    "createdAt": "...",
    "completedAt": "..."
  }
}
```

---

# 40. Threat Score Model

Recommended conceptual model:

```text
Threat Score =
    ML Risk
  + Reputation Risk
  + Domain Risk
  + Content Risk
  + Brand Impersonation Risk
  + Community Risk
```

Normalize every component to `[0,1]`.

Then:

```text
risk = weighted ensemble
```

Add calibration so:

```text
0-20   LOW
21-50  MODERATE
51-75  HIGH
76-100 CRITICAL
```

Thresholds should be configurable and evaluated experimentally.

---

# 41. Major Resume-Level Features

Prioritize these because they create strong interview talking points:

## Tier 1 — Must build

1. Multi-signal phishing detector
2. Explainable AI
3. Browser extension
4. Threat intelligence dashboard
5. Community reporting
6. Secure URL fetcher
7. Authentication/RBAC
8. Model evaluation dashboard

## Tier 2 — Strong differentiators

9. Typosquatting/brand impersonation
10. Threat graph
11. Batch analysis
12. Async job queue
13. Redis caching
14. MLOps/model registry
15. Adversarial evaluation

## Tier 3 — Exceptional

16. Safe webpage preview
17. Campaign clustering
18. Analyst case management
19. SIEM export
20. Webhook alerts
21. Email ingestion
22. Automated IOC extraction
23. Model drift monitoring

---

# 42. What YOU Should Own as the Developer

To make this genuinely your project, do not simply let an AI IDE produce the entire application and call it finished.

Your personal contribution should be concentrated in technically defensible areas.

## Ownership Area A — Detection architecture

You design:

- feature taxonomy
- scoring strategy
- ensemble architecture
- thresholding
- evaluation methodology

## Ownership Area B — Explainability

You implement:

- SHAP
- evidence ranking
- explanation schema
- human-readable reasoning

## Ownership Area C — Security engineering

You implement:

- SSRF protections
- isolated URL fetching
- input validation
- rate limiting
- secure cookies
- authorization
- audit logs

## Ownership Area D — Adversarial evaluation

You design a controlled benchmark that tests:

- obfuscation
- typosquatting
- redirects
- encoding
- domain mutations

## Ownership Area E — MLOps

You implement:

- reproducible datasets
- model versions
- experiments
- metrics
- CI model tests

These are much more valuable in interviews than simply saying "I built a React website."

---

# 43. Recommended Development Phases

## Phase 1 — Foundation

- repository setup
- monorepo
- TypeScript
- React
- Node API
- PostgreSQL
- authentication
- Docker
- CI

## Phase 2 — Detection MVP

- URL parser
- lexical features
- baseline model
- FastAPI inference
- analysis API
- results page

## Phase 3 — Intelligence

- WHOIS/RDAP
- DNS
- TLS
- reputation integrations
- domain intelligence

## Phase 4 — Explainability

- SHAP
- evidence engine
- explanation UI

## Phase 5 — Browser Extension

- Manifest V3
- active URL detection
- API integration
- threat warning UI

## Phase 6 — Community

- reports
- moderation
- reputation
- analyst dashboard

## Phase 7 — MLOps

- DVC
- MLflow
- experiment tracking
- model registry
- CI evaluation

## Phase 8 — Advanced Security

- SSRF-safe fetcher
- sandboxed analysis
- safe preview
- threat graph
- adversarial benchmark

---

# 44. Definition of Done

The project is not "done" when the UI works.

It is done when:

### Engineering

- API has validation
- tests exist
- errors are handled
- logs exist
- health checks exist
- environment variables are documented

### Security

- SSRF defenses tested
- auth tested
- RBAC tested
- rate limits tested
- secrets excluded from Git
- extension permissions minimized

### ML

- dataset documented
- train/test strategy documented
- baseline compared against improved models
- precision/recall/F1 measured
- calibration measured
- adversarial test set measured

### Product

- web app works
- extension works
- analysis history works
- reports work
- dashboard works

### Documentation

- architecture diagram
- API documentation
- threat model
- ML methodology
- model card
- deployment guide
- security assumptions
- limitations

---

# 45. Final Product Pitch

> PhishNetra is an explainable, multi-signal phishing intelligence platform that combines machine learning, domain intelligence, safe webpage analysis, reputation feeds, browser-level protection, and community threat reporting to identify and explain suspicious websites in real time.

This is substantially stronger than:

> "A website that checks whether a URL is phishing."

---

# 46. Reference-to-New-Project Mapping

| Reference | New implementation |
|---|---|
| React website | React + TypeScript analyst console |
| Express backend | TypeScript API |
| MongoDB | PostgreSQL + Prisma |
| Flask ML API | FastAPI inference service |
| Gradient Boosting | evaluated ensemble |
| 30 handcrafted features | modular feature-engineering pipeline |
| Basic report CRUD | moderated threat-intelligence reports |
| Basic typosquatting | brand impersonation engine |
| Chrome extension | real-time security extension |
| Premium boolean | subscription/feature entitlements |
| Random/ambiguous score logic | calibrated risk engine |
| direct URL fetching | isolated SSRF-safe analysis workers |
| basic dashboard | SOC-style analyst dashboard |
| no serious MLOps | DVC + MLflow + CI |
| simple explanation | SHAP + evidence graph + grounded LLM explanation |

---

# 47. Source Notes

The analysis was based on the publicly accessible reference repository and its source files.

Key reference areas inspected:

- repository README
- backend/server.js
- backend/package.json
- backend routes/controllers/models
- frontend package.json
- frontend App.js and directory structure
- FlaskBack/app.py
- FlaskBack/function_tick.py
- Chrome extension manifest and script

External security design references consulted:

- OWASP SSRF Prevention Cheat Sheet
- VirusTotal API documentation
- Chrome extension/Manifest V3 documentation

The reference repository itself is the authority for what its code currently contains; the proposed architecture is intentionally an improvement rather than a claim that these advanced features already exist.
