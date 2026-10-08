# PhishNetra — Production Deployment & Operations Guide

## 1. System Requirements

### Hardware Sizing (Single Node / Small Cluster)
- **CPU:** 4+ Cores (x86_64 / ARM64)
- **RAM:** 8GB+ (16GB recommended with full Playwright browser pooling)
- **Storage:** 50GB+ NVMe SSD (PostgreSQL WAL + Redis AOF)
- **OS:** Linux (Ubuntu 22.04 LTS / Debian 12 / Alpine) or Docker Engine 24+

---

## 2. Containerized Deployment (Docker Compose)

The complete multi-service stack can be launched using Docker Compose:

```bash
# 1. Clone repository
git clone https://github.com/Sidd-commits/PhishNetra.git
cd PhishNetra

# 2. Configure environment variables
cp .env.example .env
# Edit .env with production passwords and secrets

# 3. Build and launch all services
docker compose up -d --build

# 4. Verify service health
docker compose ps
curl -f http://localhost:5000/api/health/ready
```

### Deployed Services & Port Map
| Service | Image / Context | Internal Port | Host Port | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `postgres` | `postgres:15-alpine` | 5432 | `5432` | Relational database (Analyses, Users, Cases, Audit) |
| `redis` | `redis:7-alpine` | 6379 | `6379` | Multi-tier cache & BullMQ background worker queue |
| `ml-service` | `services/ml` | 8000 | `8000` | FastAPI ML inference, SHAP, & Playwright sandbox |
| `api` | `apps/api` | 5000 | `5000` | Node.js Express REST API & Risk Engine |
| `web` | `apps/web` | 80 | `3000` | React Vite SPA served via Nginx |

---

## 3. Kubernetes / Cloud Native Architecture

For enterprise high-availability deployments:

### Probes Configuration
```yaml
livenessProbe:
  httpGet:
    path: /api/health/live
    port: 5000
  initialDelaySeconds: 10
  periodSeconds: 15

readinessProbe:
  httpGet:
    path: /api/health/ready
    port: 5000
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Prometheus Metrics Scraping
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: phishnetra-api-metrics
spec:
  selector:
    matchLabels:
      app: phishnetra-api
  endpoints:
  - port: http
    path: /api/metrics
    interval: 15s
```

---

## 4. Environment Variables Checklist

| Variable | Required | Default / Example | Purpose |
| :--- | :--- | :--- | :--- |
| `NODE_ENV` | Yes | `production` | Enables production error masking & optimizations |
| `PORT` | Yes | `5000` | Node.js API listener port |
| `DATABASE_URL` | Yes | `postgresql://user:pass@host:5432/phishnetra` | Prisma database connection string |
| `REDIS_URL` | Optional | `redis://localhost:6379` | Redis distributed cache & queue connection |
| `ML_SERVICE_URL` | Yes | `http://localhost:8000` | URL of the Python FastAPI ML microservice |
| `JWT_SECRET` | Yes | `<cryptographic-random-string>` | Secret key used for signing authentication tokens |
| `CORS_ORIGIN` | Yes | `https://phishnetra.yourcompany.com` | Allowed CORS origins for web dashboard |
| `VIRUSTOTAL_API_KEY` | Optional | `<vt-api-key>` | Optional reputation feed provider |
