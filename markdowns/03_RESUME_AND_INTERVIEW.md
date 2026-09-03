# PhishNetra — Resume & Interview Positioning

## Recommended Project Title

**PhishNetra — Explainable Multi-Signal Phishing Intelligence Platform**

Alternative:
**PhishNetra — AI-Powered Real-Time Phishing Detection & Threat Intelligence**

---

## One-Line Description

An end-to-end phishing intelligence platform that combines ML, domain/DNS/TLS intelligence, reputation signals, explainable AI, community reporting, and a Chrome extension for real-time web protection.

---

## Resume Bullet Candidates

Use only metrics you actually measure.

### Strong default

- Built an end-to-end phishing intelligence platform combining URL ML classification, domain/DNS/TLS analysis, reputation signals, SHAP explainability, and a Manifest V3 browser extension.
- Designed an asynchronous threat-analysis pipeline with FastAPI, Node.js, PostgreSQL, Redis/BullMQ, modular feature extractors, and evidence-based risk scoring.
- Implemented typosquatting/brand-impersonation detection, SSRF-safe URL analysis, RBAC, community threat reporting, model versioning, and adversarial evaluation.

### If measured metrics exist

Replace with real numbers:

- Achieved **X% recall, Y% precision and Z PR-AUC** on a held-out phishing dataset using an ensemble detection pipeline.
- Reduced median analysis latency from **X ms to Y ms** through Redis caching and asynchronous worker execution.

Never invent these numbers.

---

# Interview Story

## Problem

Traditional URL classifiers can produce a binary prediction but do not adequately explain why a URL is suspicious and can struggle with new phishing variants.

## Solution

PhishNetra treats phishing detection as a multi-signal intelligence problem.

It combines:

```text
URL
+
Domain
+
DNS
+
TLS
+
Page
+
Reputation
+
Brand similarity
+
ML
+
Community reports
```

## Differentiator

The system explains its verdict with evidence instead of returning only:

> Phishing = True

---

# Strongest Technical Talking Points

## 1. Why multiple signals?

Because no single signal is reliable enough.

Example:

```text
HTTPS = safe-looking
but
domain age = 2 days
brand similarity = high
reputation = malicious
login form = external
```

The combined evidence is stronger.

## 2. Why not only use an LLM?

Because LLMs are not ideal as deterministic security classifiers.

Use ML/deterministic rules for the verdict and LLMs only for grounded explanation.

## 3. Why FastAPI?

Separates Python ML/inference concerns from the TypeScript application backend.

## 4. Why Redis/BullMQ?

Deep analysis involves network-bound and expensive operations.

Asynchronous workers prevent long-running analysis from blocking API requests.

## 5. Why PostgreSQL?

Threat intelligence is relational:

```text
domain → IP
domain → certificate
domain → report
domain → brand
analysis → evidence
user → report
```

Relational constraints and querying are useful.

## 6. Why SHAP?

The security analyst needs to understand which features contributed to a prediction.

## 7. Why browser extension?

It moves detection from a website users have to visit into the browsing workflow.

---

# Security Questions You Should Be Able to Answer

### What is SSRF?

A server is tricked into making network requests to unintended destinations.

This project is especially exposed because it analyzes attacker-controlled URLs.

### How do you defend against it?

- validate schemes
- block private/loopback/link-local addresses
- resolve DNS safely
- validate resolved IPs
- restrict redirects
- limit ports
- timeout requests
- isolate the fetcher

### Why is HTTPS insufficient?

HTTPS authenticates the encrypted connection to the domain/certificate. It does not prove that the domain itself is trustworthy.

### What is a false negative?

A malicious URL classified as safe.

For security products, this can be more dangerous than a false positive, so recall is important.

### What is calibration?

Whether predicted probabilities correspond to observed frequencies.

A model saying "90% malicious" should actually be approximately that reliable over comparable predictions.

---

# What Makes This a Major Project

A basic phishing classifier is:

```text
dataset → model → prediction
```

PhishNetra should be:

```text
data engineering
      ↓
feature engineering
      ↓
ML experimentation
      ↓
model evaluation
      ↓
secure distributed analysis
      ↓
threat intelligence
      ↓
explainability
      ↓
web application
      ↓
browser extension
      ↓
MLOps
      ↓
monitoring
```

That breadth is what makes it suitable as a major project and strong resume material.
