# PhishNetra — Legal Takedown Center, Multi-Tenant Workspaces & Executive Intelligence

**Milestone:** Milestone 12  
**Specification:** Autonomous RFC 2142 Abuse Notice Generation, Multi-Tenant RBAC Governance & Board-Level Executive Dossiers  

---

## 1. Executive Overview

PhishNetra Milestone 12 expands the platform from proactive threat mitigation into **active adversary disruption** and **enterprise executive governance**:
1. **Autonomous RFC 2142 Legal Abuse Dispatcher:** Automatically formats standardized abuse mailbox notices (`abuse@registrar`, `abuse@host`), calculates unique tracking IDs (`TKD-XXXX-XXXXXX`), compiles zero-trust forensic evidence attachments, and tracks resolution lifecycles from dispatch to domain suspension.
2. **Multi-Tenant Organization & Team Workspaces:** Role-Based Access Control (RBAC) supporting `OWNER`, `SECURITY_ADMIN`, `SOC_ANALYST`, `AUDITOR`, and `VIEWER` roles, quota enforcement, IP allowlisting, and mandatory MFA policy toggles.
3. **Autonomous Executive Intelligence Dossiers:** Aggregates C-suite metrics (Inbound Scans, Phishing Intercepted, Zero-Day Variants Caught, Mean Time to Neutralize, Mitigation Efficacy %), targeted corporate brand attack volume distribution, adversary threat campaign attribution, and 1-click exportable Board-ready Markdown dossiers.

---

## 2. Architecture & Data Contracts

### 2.1 Takedown Notice Lifecycle Schema (`@phishnetra/shared`)
```typescript
export const TakedownNoticeTypeSchema = z.enum([
  'RFC2142_ABUSE_NOTICE',
  'ICANN_URS_COMPLAINT',
  'DMCA_512C_TAKEDOWN',
  'TRADEMARK_INFRINGEMENT',
  'REGISTRAR_SUSPENSION_REQUEST'
]);

export const TakedownStatusSchema = z.enum([
  'DRAFTED',
  'PENDING_APPROVAL',
  'DISPATCHED',
  'ACKNOWLEDGED',
  'DOMAIN_SUSPENDED',
  'REJECTED'
]);
```

### 2.2 Organization & RBAC Model
```typescript
export const OrganizationRoleSchema = z.enum([
  'OWNER',
  'SECURITY_ADMIN',
  'SOC_ANALYST',
  'AUDITOR',
  'VIEWER'
]);
```

### 2.3 Executive Threat Report Contract
```typescript
export const ExecutiveThreatReportSchema = z.object({
  reportId: z.string(),
  organizationName: z.string(),
  generatedAt: z.string(),
  timeRange: z.string(),
  metrics: z.object({
    totalScans: z.number().int(),
    phishingIntercepted: z.number().int(),
    zeroDayIdentified: z.number().int(),
    meanTimeToNeutralizeMinutes: z.number(),
    mitigationSuccessRatePercent: z.number()
  }),
  topTargetedBrands: z.array(z.object({
    brand: z.string(),
    incidentCount: z.number().int(),
    riskPercentage: z.number()
  })),
  criticalCampaigns: z.array(z.object({
    campaignName: z.string(),
    threatActorOrigin: z.string(),
    iocCount: z.number().int(),
    severity: RiskLevelSchema
  })),
  strategicRecommendations: z.array(z.string())
});
```

---

## 3. REST API Endpoints

### 3.1 Legal Takedowns (`/api/takedowns`)
- `GET /api/takedowns` — List takedown notices with optional `?status=` filtering.
- `GET /api/takedowns/:id` — Retrieve notice payload, evidence, and tracking details.
- `POST /api/takedowns` — Draft or auto-dispatch new legal notice.
- `PATCH /api/takedowns/:id/status` — Transition notice lifecycle status.

### 3.2 Organization & Workspaces (`/api/organizations`)
- `GET /api/organizations/workspace` — Get organization profile, quotas, members, and security policies.
- `PATCH /api/organizations/policy` — Update workspace security configuration (MFA, IP allowlist, auto-sinkholing).
- `POST /api/organizations/members` — Invite a new team member with assigned RBAC role.
- `DELETE /api/organizations/members/:id` — Revoke team member workspace access.

### 3.3 Executive Threat Intelligence (`/api/reports/executive`)
- `GET /api/reports/executive` — Returns JSON aggregated CISO briefing and brand metrics.
- `GET /api/reports/executive/download/markdown` — Generates and downloads board-ready Markdown file.

---

## 4. UI & React SOC Experience

1. **Legal Takedown Center (`/takedowns`):** Split-view console showing notice tracking badges, RFC 2142 body text, registrar abuse mailbox addresses, and 1-click status transitions.
2. **Organization & Team Workspaces (`/organization`):** Quota consumption meters, member management table with RBAC badges, and security policy switches.
3. **Executive Threat Intelligence Dossier (`/executive-briefing`):** KPI cards, brand attack share meters, threat cluster breakdown, strategic recommendations, and 1-click Markdown export.

---

## 5. Automated Verification & Metrics

- **Unit & Integration Test Suite (`apps/api/tests/takedown_and_orgs.test.ts`):** 10 tests verifying full lifecycle workflows.
- **Total Monorepo Passing Tests:** **169 / 169 Tests Passing (100%)**
  - Node.js API: 19 test suites, 99 tests passed
  - Python ML: 58 tests passed
  - Extension: 12 tests passed
