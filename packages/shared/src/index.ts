import { z } from 'zod';

// ============================================================================
// Enums & Literals
// ============================================================================

export const ThreatVerdictSchema = z.enum(['SAFE', 'SUSPICIOUS', 'PHISHING', 'UNKNOWN']);
export type ThreatVerdict = z.infer<typeof ThreatVerdictSchema>;

export const RiskLevelSchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const EvidenceSeveritySchema = z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type EvidenceSeverity = z.infer<typeof EvidenceSeveritySchema>;

export const DetectionLayerSchema = z.enum([
  'URL',
  'DOMAIN',
  'DNS',
  'TLS',
  'REPUTATION',
  'ML',
  'CONTENT',
  'FORM',
  'BRAND',
  'NETWORK'
]);
export type DetectionLayer = z.infer<typeof DetectionLayerSchema>;

export const LayerStatusSchema = z.enum(['SUCCESS', 'PARTIAL', 'NOT_CONFIGURED', 'FAILED', 'SKIPPED']);
export type LayerStatus = z.infer<typeof LayerStatusSchema>;

export const PageAnalysisStatusSchema = z.enum([
  'NOT_REQUESTED',
  'QUEUED',
  'RUNNING',
  'COMPLETED',
  'FAILED',
  'BLOCKED',
  'TIMEOUT',
  'PARTIAL',
  'SKIPPED'
]);
export type PageAnalysisStatus = z.infer<typeof PageAnalysisStatusSchema>;

export const UserRoleSchema = z.enum(['USER', 'ANALYST', 'ADMIN']);
export type UserRole = z.infer<typeof UserRoleSchema>;

// ============================================================================
// Evidence Item Schema (Layer-Aware)
// ============================================================================

export const EvidenceItemSchema = z.object({
  layer: DetectionLayerSchema.default('URL'),
  featureKey: z.string(),
  featureValue: z.union([z.string(), z.number(), z.boolean()]),
  severity: EvidenceSeveritySchema,
  description: z.string(),
  contribution: z.number().min(0).max(1).optional().default(0),
  source: z.string().optional().default('RuleEngine'),
  confidence: z.number().min(0).max(1).optional().default(1.0)
});
export type EvidenceItem = z.infer<typeof EvidenceItemSchema>;

// ============================================================================
// URL Feature Vector Schema (Deterministic Features)
// ============================================================================

export const URLFeatureVectorSchema = z.object({
  url_length: z.number(),
  hostname_length: z.number(),
  path_length: z.number(),
  query_length: z.number(),
  subdomain_count: z.number(),
  has_ip_address: z.number().int().min(0).max(1),
  has_https: z.number().int().min(0).max(1),
  special_char_count: z.number(),
  digit_count: z.number(),
  hyphen_count: z.number(),
  at_symbol_count: z.number(),
  double_slash_in_path: z.number().int().min(0).max(1),
  encoded_char_count: z.number(),
  suspicious_keyword_count: z.number(),
  entropy: z.number(),
  tld_in_subdomain: z.number().int().min(0).max(1),
  port_in_url: z.number().int().min(0).max(1),
  tld_length: z.number()
});
export type URLFeatureVector = z.infer<typeof URLFeatureVectorSchema>;

// ============================================================================
// Content Feature Vector Schema (Milestone 3)
// ============================================================================

export const ContentFeatureVectorSchema = z.object({
  forms_count: z.number(),
  password_inputs: z.number(),
  text_inputs: z.number(),
  hidden_inputs: z.number(),
  has_login_form: z.number().int().min(0).max(1),
  external_form_actions: z.number(),
  iframe_count: z.number(),
  hidden_iframe_count: z.number(),
  external_iframe_count: z.number(),
  script_count: z.number(),
  external_script_count: z.number(),
  obfuscated_script_count: z.number(),
  external_domain_count: z.number(),
  suspicious_keyword_count: z.number(),
  urgency_score: z.number(),
  brand_reference_count: z.number(),
  brand_domain_mismatch: z.number().int().min(0).max(1),
  redirect_count: z.number(),
  suspicious_link_count: z.number(),
  page_text_length: z.number()
});
export type ContentFeatureVector = z.infer<typeof ContentFeatureVectorSchema>;

// ============================================================================
// Multi-Layer Intelligence Result Schemas
// ============================================================================

// Layer 1: URL Intelligence
export const URLIntelligenceSchema = z.object({
  status: LayerStatusSchema,
  canonicalUrl: z.string(),
  hostname: z.string(),
  path: z.string(),
  query: z.string(),
  isShortener: z.boolean(),
  shortenerProvider: z.string().nullable().optional(),
  isPunycode: z.boolean(),
  unicodeHostname: z.string().nullable().optional(),
  hasUserInfo: z.boolean(),
  hasCustomPort: z.boolean(),
  customPort: z.number().nullable().optional(),
  obfuscatedEncodings: z.array(z.string()),
  digitRatio: z.number(),
  specialCharRatio: z.number(),
  hyphenRatio: z.number(),
  entropy: z.number(),
  features: URLFeatureVectorSchema
});
export type URLIntelligence = z.infer<typeof URLIntelligenceSchema>;

// Layer 2: Domain Intelligence (RDAP / Registration)
export const DomainIntelligenceSchema = z.object({
  status: LayerStatusSchema,
  domain: z.string(),
  registrableDomain: z.string(),
  tld: z.string(),
  subdomain: z.string(),
  registrar: z.string().nullable().optional(),
  creationDate: z.string().nullable().optional(),
  expirationDate: z.string().nullable().optional(),
  domainAgeDays: z.number().nullable().optional(),
  domainAgeCategory: z.enum(['< 30 days', '30–90 days', '90–365 days', '> 365 days', 'unknown']),
  isPrivacyProtected: z.boolean(),
  rawStatus: z.string().optional()
});
export type DomainIntelligence = z.infer<typeof DomainIntelligenceSchema>;

// Layer 3: DNS & IP Intelligence
export const IPDetailSchema = z.object({
  ip: z.string(),
  version: z.enum(['IPv4', 'IPv6']),
  asn: z.string().nullable().optional(),
  org: z.string().nullable().optional(),
  country: z.string().nullable().optional()
});
export type IPDetail = z.infer<typeof IPDetailSchema>;

export const DNSIntelligenceSchema = z.object({
  status: LayerStatusSchema,
  resolvedIps: z.array(z.string()),
  ipv4Count: z.number(),
  ipv6Count: z.number(),
  nameservers: z.array(z.string()),
  mxRecords: z.array(z.string()),
  cnameRecords: z.array(z.string()),
  txtRecords: z.array(z.string()),
  hasMx: z.boolean(),
  ipDetails: z.array(IPDetailSchema),
  error: z.string().nullable().optional()
});
export type DNSIntelligence = z.infer<typeof DNSIntelligenceSchema>;

// Layer 4: TLS / SSL Intelligence
export const TLSIntelligenceSchema = z.object({
  status: LayerStatusSchema,
  hasTls: z.boolean(),
  certificateValid: z.boolean(),
  certificateExpired: z.boolean(),
  hostnameMatches: z.boolean(),
  validFrom: z.string().nullable().optional(),
  validTo: z.string().nullable().optional(),
  daysUntilExpiry: z.number().nullable().optional(),
  issuer: z.string().nullable().optional(),
  subject: z.string().nullable().optional(),
  sans: z.array(z.string()),
  tlsVersion: z.string().nullable().optional(),
  zeroTrustWarning: z.string(),
  error: z.string().nullable().optional()
});
export type TLSIntelligence = z.infer<typeof TLSIntelligenceSchema>;

// Layer 5: Reputation Intelligence
export const ReputationProviderResultSchema = z.object({
  providerName: z.string(),
  status: LayerStatusSchema,
  isConfigured: z.boolean(),
  malicious: z.boolean(),
  suspicious: z.boolean(),
  harmless: z.boolean(),
  threatType: z.string().nullable().optional(),
  confidence: z.number(),
  details: z.string().optional()
});
export type ReputationProviderResult = z.infer<typeof ReputationProviderResultSchema>;

export const ReputationIntelligenceSchema = z.object({
  status: LayerStatusSchema,
  providers: z.array(ReputationProviderResultSchema),
  isListedMalicious: z.boolean(),
  reputationScore: z.number().min(0).max(100)
});
export type ReputationIntelligence = z.infer<typeof ReputationIntelligenceSchema>;

// Layer 6: ML Prediction
export const MLIntelligenceSchema = z.object({
  status: LayerStatusSchema,
  phishingProbability: z.number().min(0).max(1),
  confidence: z.number().min(0).max(1),
  predictedLabel: z.number().int(),
  modelVersion: z.string(),
  inferenceTimeMs: z.number()
});
export type MLIntelligence = z.infer<typeof MLIntelligenceSchema>;

// ============================================================================
// Page / Content Analysis Schemas (Milestone 3)
// ============================================================================

export const RedirectHopSchema = z.object({
  url: z.string(),
  status: z.number().optional(),
  ip: z.string().optional(),
  headers: z.record(z.string(), z.string()).optional()
});
export type RedirectHop = z.infer<typeof RedirectHopSchema>;

export const FormFindingSchema = z.object({
  id: z.string().optional(),
  name: z.string().optional(),
  action: z.string(),
  actionResolved: z.string(),
  method: z.string().default('GET'),
  target: z.string().optional(),
  isCrossOrigin: z.boolean(),
  isIpAction: z.boolean(),
  hasPasswordField: z.boolean(),
  hasEmailField: z.boolean(),
  hasCreditCardField: z.boolean(),
  hasOtpField: z.boolean(),
  passwordFieldCount: z.number().default(0),
  inputCount: z.number().default(0),
  description: z.string().optional()
});
export type FormFinding = z.infer<typeof FormFindingSchema>;

export const IFrameFindingSchema = z.object({
  src: z.string().nullable().optional(),
  srcResolved: z.string().nullable().optional(),
  isCrossOrigin: z.boolean(),
  isHidden: z.boolean(),
  width: z.string().optional(),
  height: z.string().optional()
});
export type IFrameFinding = z.infer<typeof IFrameFindingSchema>;

export const ScriptFindingSchema = z.object({
  src: z.string().nullable().optional(),
  isExternal: z.boolean(),
  hasObfuscation: z.boolean(),
  hasEval: z.boolean(),
  hasDocumentWrite: z.boolean(),
  hasSuspiciousRedirect: z.boolean(),
  reasons: z.array(z.string()).default([])
});
export type ScriptFinding = z.infer<typeof ScriptFindingSchema>;

export const BrandFindingSchema = z.object({
  claimedBrand: z.string(),
  authenticDomain: z.string(),
  actualDomain: z.string(),
  isMismatch: z.boolean(),
  confidence: z.number().min(0).max(1),
  matchSources: z.array(z.string()).default([]),
  description: z.string().optional()
});
export type BrandFinding = z.infer<typeof BrandFindingSchema>;

export const KeywordFindingSchema = z.object({
  category: z.string(),
  count: z.number(),
  matchedTerms: z.array(z.string()).default([])
});
export type KeywordFinding = z.infer<typeof KeywordFindingSchema>;

export const DOMMetricsSchema = z.object({
  nodeCount: z.number().default(0),
  depth: z.number().default(0),
  formsCount: z.number().default(0),
  inputsCount: z.number().default(0),
  passwordInputsCount: z.number().default(0),
  hiddenInputsCount: z.number().default(0),
  iframesCount: z.number().default(0),
  scriptsCount: z.number().default(0),
  externalScriptsCount: z.number().default(0),
  linksCount: z.number().default(0),
  externalLinksCount: z.number().default(0),
  suspiciousLinksCount: z.number().default(0)
});
export type DOMMetrics = z.infer<typeof DOMMetricsSchema>;

export const NetworkMetricsSchema = z.object({
  totalRequests: z.number().default(0),
  uniqueDomains: z.array(z.string()).default([]),
  thirdPartyDomains: z.array(z.string()).default([]),
  scriptsLoaded: z.number().default(0),
  iframesLoaded: z.number().default(0),
  externalFormActions: z.number().default(0),
  blockedRequestsCount: z.number().default(0)
});
export type NetworkMetrics = z.infer<typeof NetworkMetricsSchema>;

export const ScreenshotMetadataSchema = z.object({
  available: z.boolean().default(false),
  width: z.number().default(1280),
  height: z.number().default(800),
  mimeType: z.string().optional(),
  base64Preview: z.string().optional(),
  storagePath: z.string().optional()
});
export type ScreenshotMetadata = z.infer<typeof ScreenshotMetadataSchema>;

export const PageAnalysisResultSchema = z.object({
  status: PageAnalysisStatusSchema,
  requestedUrl: z.string(),
  finalUrl: z.string().nullable().optional(),
  pageTitle: z.string().nullable().optional(),
  redirectCount: z.number().default(0),
  redirectChain: z.array(RedirectHopSchema).default([]),
  domMetrics: DOMMetricsSchema.nullable().optional(),
  forms: z.array(FormFindingSchema).default([]),
  iframes: z.array(IFrameFindingSchema).default([]),
  scripts: z.array(ScriptFindingSchema).default([]),
  keywords: z.array(KeywordFindingSchema).default([]),
  brandFindings: z.array(BrandFindingSchema).default([]),
  networkMetrics: NetworkMetricsSchema.nullable().optional(),
  contentFeatures: ContentFeatureVectorSchema.nullable().optional(),
  screenshot: ScreenshotMetadataSchema.nullable().optional(),
  urgencyScore: z.number().default(0),
  contentRiskScore: z.number().min(0).max(100).default(0),
  phishingProbability: z.number().min(0).max(1).default(0),
  confidence: z.number().min(0).max(1).default(1.0),
  error: z.string().nullable().optional(),
  blockReason: z.string().nullable().optional(),
  acquisitionTimeMs: z.number().default(0)
});
export type PageAnalysisResult = z.infer<typeof PageAnalysisResultSchema>;

// Combined Multi-Layer Result
export const MultiLayerDataSchema = z.object({
  url: URLIntelligenceSchema,
  domain: DomainIntelligenceSchema,
  dns: DNSIntelligenceSchema,
  tls: TLSIntelligenceSchema,
  reputation: ReputationIntelligenceSchema,
  ml: MLIntelligenceSchema,
  page: PageAnalysisResultSchema.optional()
});
export type MultiLayerData = z.infer<typeof MultiLayerDataSchema>;

// ============================================================================
// ML API Microservice Contracts
// ============================================================================

export const MLPredictionRequestSchema = z.object({
  url: z.string().min(1)
});
export type MLPredictionRequest = z.infer<typeof MLPredictionRequestSchema>;

export const MLPredictionResponseSchema = z.object({
  url: z.string(),
  normalized_url: z.string(),
  features: URLFeatureVectorSchema,
  phishing_probability: z.number().min(0).max(1),
  confidence: z.number().min(0).max(1),
  predicted_label: z.number().int(),
  model_version: z.string(),
  inference_time_ms: z.number()
});
export type MLPredictionResponse = z.infer<typeof MLPredictionResponseSchema>;

export const PageAnalysisRequestSchema = z.object({
  url: z.string().min(1),
  timeout_ms: z.number().optional().default(10000),
  capture_screenshot: z.boolean().optional().default(false)
});
export type PageAnalysisRequest = z.infer<typeof PageAnalysisRequestSchema>;

// ============================================================================
// Analysis API Response Contracts
// ============================================================================

export const AnalysisRequestSchema = z.object({
  url: z.string().url('Invalid URL format. Please provide a complete URL starting with http:// or https://'),
  analyzePage: z.boolean().optional().default(true)
});
export type AnalysisRequest = z.infer<typeof AnalysisRequestSchema>;

export const AnalysisResponseSchema = z.object({
  analysisId: z.string(),
  url: z.string(),
  normalizedUrl: z.string(),
  verdict: ThreatVerdictSchema,
  riskScore: z.number().min(0).max(100),
  riskLevel: RiskLevelSchema,
  confidence: z.number().min(0).max(1),
  mlProbability: z.number().min(0).max(1),
  layers: MultiLayerDataSchema.optional(),
  layerStatuses: z.record(z.string(), LayerStatusSchema).optional(),
  pageAnalysis: PageAnalysisResultSchema.optional(),
  evidence: z.array(EvidenceItemSchema),
  features: URLFeatureVectorSchema.optional(),
  summary: z.string().optional(),
  createdAt: z.string()
});
export type AnalysisResponse = z.infer<typeof AnalysisResponseSchema>;

export const AnalysisSummarySchema = z.object({
  id: z.string(),
  url: z.string(),
  verdict: ThreatVerdictSchema,
  riskScore: z.number(),
  riskLevel: RiskLevelSchema,
  confidence: z.number(),
  pageStatus: PageAnalysisStatusSchema.optional(),
  createdAt: z.string()
});
export type AnalysisSummary = z.infer<typeof AnalysisSummarySchema>;

// ============================================================================
// Authentication Schemas
// ============================================================================

export const RegisterRequestSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters long').max(60),
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters long')
});
export type RegisterRequest = z.infer<typeof RegisterRequestSchema>;

export const LoginRequestSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(1, 'Password is required')
});
export type LoginRequest = z.infer<typeof LoginRequestSchema>;

export const UserProfileSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string(),
  role: UserRoleSchema,
  createdAt: z.string()
});
export type UserProfile = z.infer<typeof UserProfileSchema>;

export const AuthResponseSchema = z.object({
  user: UserProfileSchema,
  token: z.string()
});
export type AuthResponse = z.infer<typeof AuthResponseSchema>;

// ============================================================================
// Multi-Layer Risk Engine Configurable Thresholds & Weights
// ============================================================================

export const LAYER_WEIGHTS = {
  URL: 0.15,
  DOMAIN: 0.10,
  DNS: 0.08,
  TLS: 0.07,
  REPUTATION: 0.20,
  ML: 0.15,
  CONTENT: 0.15,
  BRAND: 0.10
} as const;

export const RISK_THRESHOLDS = {
  SAFE_MAX: 29.99,
  SUSPICIOUS_MAX: 59.99,
  HIGH_MAX: 79.99
} as const;

// ============================================================================
// Milestone 4: Batch Processing & Async Jobs
// ============================================================================

export const BatchJobStatusSchema = z.enum([
  'QUEUED',
  'RUNNING',
  'COMPLETED',
  'PARTIAL',
  'FAILED',
  'CANCELLED'
]);
export type BatchJobStatus = z.infer<typeof BatchJobStatusSchema>;

export const BatchItemStatusSchema = z.enum([
  'QUEUED',
  'RUNNING',
  'COMPLETED',
  'FAILED'
]);
export type BatchItemStatus = z.infer<typeof BatchItemStatusSchema>;

export const BatchJobRequestSchema = z.object({
  urls: z.union([
    z.array(z.string().min(1)),
    z.string().min(1)
  ]),
  includePageAnalysis: z.boolean().optional(),
  tags: z.array(z.string()).optional()
});
export type BatchJobRequest = z.infer<typeof BatchJobRequestSchema>;

export const BatchItemResultSchema = z.object({
  id: z.string(),
  batchJobId: z.string(),
  url: z.string(),
  normalizedUrl: z.string().optional().nullable(),
  status: BatchItemStatusSchema,
  riskScore: z.number().optional().nullable(),
  verdict: ThreatVerdictSchema.optional().nullable(),
  riskLevel: RiskLevelSchema.optional().nullable(),
  confidence: z.number().optional().nullable(),
  errorMessage: z.string().optional().nullable(),
  analysisId: z.string().optional().nullable(),
  createdAt: z.string(),
  updatedAt: z.string().optional()
});
export type BatchItemResult = z.infer<typeof BatchItemResultSchema>;

export const BatchJobResponseSchema = z.object({
  id: z.string(),
  userId: z.string().optional().nullable(),
  status: BatchJobStatusSchema,
  totalUrls: z.number().int().min(0),
  processedUrls: z.number().int().min(0),
  safeCount: z.number().int().min(0),
  suspiciousCount: z.number().int().min(0),
  phishingCount: z.number().int().min(0),
  failedCount: z.number().int().min(0),
  avgRiskScore: z.number().min(0).max(100),
  progressPercent: z.number().min(0).max(100),
  includePageAnalysis: z.boolean().optional().default(false),
  createdAt: z.string(),
  updatedAt: z.string(),
  completedAt: z.string().optional().nullable(),
  items: z.array(BatchItemResultSchema).optional()
});
export type BatchJobResponse = z.infer<typeof BatchJobResponseSchema>;

// ============================================================================
// Milestone 4: Typosquatting & Homoglyph Engine
// ============================================================================

export const TyposquattingTypeSchema = z.enum([
  'HOMOGLYPH',
  'LEVENSHTEIN',
  'BIT_FLIP',
  'SUBDOMAIN',
  'COMBOSQUAT',
  'OMISSION',
  'REPETITION'
]);
export type TyposquattingType = z.infer<typeof TyposquattingTypeSchema>;

export const TyposquattingMatchSchema = z.object({
  variant: z.string(),
  targetBrand: z.string(),
  officialDomain: z.string(),
  type: TyposquattingTypeSchema,
  distance: z.number().optional(),
  similarityScore: z.number().min(0).max(100),
  isResolving: z.boolean().optional(),
  ipAddress: z.string().optional().nullable(),
  riskLevel: RiskLevelSchema,
  explanation: z.string()
});
export type TyposquattingMatch = z.infer<typeof TyposquattingMatchSchema>;

export const TyposquattingScanResultSchema = z.object({
  queryDomain: z.string(),
  detectedTargetBrand: z.string().optional().nullable(),
  isDirectImpersonation: z.boolean(),
  totalVariantsGenerated: z.number(),
  matches: z.array(TyposquattingMatchSchema)
});
export type TyposquattingScanResult = z.infer<typeof TyposquattingScanResultSchema>;

// ============================================================================
// Milestone 4: Domain Dossier Hub
// ============================================================================

export const DomainDossierSchema = z.object({
  domain: z.string(),
  registrableDomain: z.string(),
  domainAgeDays: z.number().optional().nullable(),
  ageCategory: z.string().optional().nullable(),
  registrar: z.string().optional().nullable(),
  nameservers: z.array(z.string()),
  ipAddresses: z.array(z.string()),
  totalScans: z.number().int().min(0),
  phishingScans: z.number().int().min(0),
  riskScore: z.number().min(0).max(100),
  riskLevel: RiskLevelSchema,
  reputationStatus: z.string(),
  typosquattingAlerts: z.array(TyposquattingMatchSchema),
  recentAnalyses: z.array(AnalysisSummarySchema),
  communityReportsCount: z.number().int().min(0),
  createdAt: z.string()
});
export type DomainDossier = z.infer<typeof DomainDossierSchema>;

// ============================================================================
// Milestone 4: Community Threat Reports & Moderation Hub
// ============================================================================

export const ReportTypeSchema = z.enum([
  'PHISHING',
  'MALWARE',
  'SCAM',
  'FALSE_POSITIVE',
  'CREDENTIAL_HARVEST'
]);
export type ReportType = z.infer<typeof ReportTypeSchema>;

export const ReportStatusSchema = z.enum([
  'PENDING',
  'APPROVED',
  'REJECTED',
  'RESOLVED'
]);
export type ReportStatus = z.infer<typeof ReportStatusSchema>;

export const CreateReportRequestSchema = z.object({
  url: z.string().min(3, 'URL is required'),
  domain: z.string().optional(),
  reportType: ReportTypeSchema,
  description: z.string().min(5, 'Please provide detailed context for your report').max(2000),
  evidenceDetails: z.string().max(5000).optional()
});
export type CreateReportRequest = z.infer<typeof CreateReportRequestSchema>;

export const ReportModerationRequestSchema = z.object({
  status: ReportStatusSchema,
  moderatorNotes: z.string().max(2000).optional()
});
export type ReportModerationRequest = z.infer<typeof ReportModerationRequestSchema>;

export const CommunityReportSchema = z.object({
  id: z.string(),
  userId: z.string().optional().nullable(),
  userName: z.string().optional().nullable(),
  domain: z.string(),
  url: z.string(),
  reportType: ReportTypeSchema,
  description: z.string(),
  evidenceDetails: z.string().optional().nullable(),
  status: ReportStatusSchema,
  moderatorNotes: z.string().optional().nullable(),
  moderatedBy: z.string().optional().nullable(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type CommunityReport = z.infer<typeof CommunityReportSchema>;

// ============================================================================
// Milestone 4: Queue & Cache Observability Metrics
// ============================================================================

export const QueueMetricsSchema = z.object({
  waiting: z.number().int().min(0),
  active: z.number().int().min(0),
  completed: z.number().int().min(0),
  failed: z.number().int().min(0),
  isPaused: z.boolean(),
  workerConcurrency: z.number().int().min(1),
  driver: z.string()
});
export type QueueMetrics = z.infer<typeof QueueMetricsSchema>;

export const CacheStatsSchema = z.object({
  hits: z.number().int().min(0),
  misses: z.number().int().min(0),
  keysCount: z.number().int().min(0),
  memoryUsageMb: z.number().min(0),
  hitRatio: z.number().min(0).max(1),
  driver: z.string()
});
export type CacheStats = z.infer<typeof CacheStatsSchema>;

// ============================================================================
// Milestone 6: Threat Graph Engine & Infrastructure Correlation
// ============================================================================

export const GraphNodeTypeSchema = z.enum([
  'DOMAIN',
  'IP',
  'ASN',
  'CERTIFICATE',
  'NAMESERVER',
  'REGISTRAR',
  'BRAND',
  'CAMPAIGN',
  'URL'
]);
export type GraphNodeType = z.infer<typeof GraphNodeTypeSchema>;

export const GraphEdgeTypeSchema = z.enum([
  'RESOLVES_TO',
  'HOSTED_ON',
  'USES_CERTIFICATE',
  'MANAGED_BY_NS',
  'REGISTERED_THROUGH',
  'REDIRECTS_TO',
  'EMBEDS_SCRIPT',
  'IMPERSONATES',
  'PART_OF_CAMPAIGN',
  'CO_LOCATED_WITH'
]);
export type GraphEdgeType = z.infer<typeof GraphEdgeTypeSchema>;

export const GraphNodeSchema = z.object({
  id: z.string(),
  label: z.string(),
  type: GraphNodeTypeSchema,
  riskScore: z.number().min(0).max(100).optional(),
  riskLevel: RiskLevelSchema.optional(),
  properties: z.record(z.string(), z.any()).default({}),
  firstSeen: z.string(),
  lastSeen: z.string()
});
export type GraphNode = z.infer<typeof GraphNodeSchema>;

export const GraphEdgeSchema = z.object({
  id: z.string(),
  source: z.string(),
  target: z.string(),
  type: GraphEdgeTypeSchema,
  weight: z.number().default(1.0),
  properties: z.record(z.string(), z.any()).optional().default({}),
  firstSeen: z.string(),
  lastSeen: z.string()
});
export type GraphEdge = z.infer<typeof GraphEdgeSchema>;

export const GraphDataSchema = z.object({
  nodes: z.array(GraphNodeSchema),
  edges: z.array(GraphEdgeSchema),
  stats: z.object({
    totalNodes: z.number().int(),
    totalEdges: z.number().int(),
    domainCount: z.number().int().optional(),
    ipCount: z.number().int().optional(),
    campaignCount: z.number().int().optional()
  }).optional()
});
export type GraphData = z.infer<typeof GraphDataSchema>;

export const CampaignStatusSchema = z.enum(['ACTIVE', 'DORMANT', 'NEUTRALIZED']);
export type CampaignStatus = z.infer<typeof CampaignStatusSchema>;

export const ThreatCampaignSchema = z.object({
  id: z.string(),
  name: z.string(),
  threatActor: z.string().optional().nullable(),
  targetedBrands: z.array(z.string()),
  riskLevel: RiskLevelSchema,
  severityScore: z.number().min(0).max(100),
  status: CampaignStatusSchema,
  domainCount: z.number().int().min(0),
  ipCount: z.number().int().min(0),
  iocs: z.object({
    domains: z.array(z.string()),
    ips: z.array(z.string()),
    asns: z.array(z.string()),
    nameservers: z.array(z.string()).optional()
  }),
  description: z.string(),
  firstSeen: z.string(),
  lastSeen: z.string(),
  stixBundle: z.record(z.string(), z.any()).optional()
});
export type ThreatCampaign = z.infer<typeof ThreatCampaignSchema>;

export const CampaignClusterResultSchema = z.object({
  totalCampaigns: z.number().int().min(0),
  newCampaignsCreated: z.number().int().min(0),
  domainsClustered: z.number().int().min(0),
  campaigns: z.array(ThreatCampaignSchema)
});
export type CampaignClusterResult = z.infer<typeof CampaignClusterResultSchema>;

// ============================================================================
// Milestone 7: MLOps, Continuous Retraining, SHAP & Adversarial Hardening
// ============================================================================

export const SHAPFeatureAttributionSchema = z.object({
  featureName: z.string(),
  featureValue: z.union([z.string(), z.number(), z.boolean()]),
  shapValue: z.number(),
  direction: z.enum(['PHISHING', 'BENIGN']),
  contributionPercent: z.number().min(0).max(100),
  humanDescription: z.string()
});
export type SHAPFeatureAttribution = z.infer<typeof SHAPFeatureAttributionSchema>;

export const SHAPExplanationSchema = z.object({
  url: z.string(),
  baseValue: z.number(),
  predictedProbability: z.number().min(0).max(1),
  predictedLabel: z.number().int(),
  modelVersion: z.string(),
  attributions: z.array(SHAPFeatureAttributionSchema),
  topPhishingFactors: z.array(z.string()),
  topBenignFactors: z.array(z.string()),
  narrativeSummary: z.string()
});
export type SHAPExplanation = z.infer<typeof SHAPExplanationSchema>;

export const ModelMetadataSchema = z.object({
  version: z.string(),
  algorithm: z.string(),
  trainedAt: z.string(),
  active: z.boolean(),
  datasetSamples: z.number().int(),
  accuracy: z.number().min(0).max(1),
  precision: z.number().min(0).max(1),
  recall: z.number().min(0).max(1),
  f1Score: z.number().min(0).max(1),
  rocAuc: z.number().min(0).max(1),
  artifactPath: z.string().optional(),
  featureCount: z.number().int().optional()
});
export type ModelMetadata = z.infer<typeof ModelMetadataSchema>;

export const ModelRegistryOverviewSchema = z.object({
  activeModel: ModelMetadataSchema.optional().nullable(),
  registeredModels: z.array(ModelMetadataSchema),
  totalModels: z.number().int()
});
export type ModelRegistryOverview = z.infer<typeof ModelRegistryOverviewSchema>;

export const DriftFeatureMetricSchema = z.object({
  featureName: z.string(),
  psiScore: z.number().min(0),
  ksStatistic: z.number().min(0).max(1),
  pValue: z.number().min(0).max(1),
  isDrifted: z.boolean(),
  status: z.enum(['STABLE', 'MODERATE', 'DRIFTED'])
});
export type DriftFeatureMetric = z.infer<typeof DriftFeatureMetricSchema>;

export const DriftReportSchema = z.object({
  generatedAt: z.string(),
  overallDriftStatus: z.enum(['STABLE', 'MODERATE', 'CRITICAL']),
  baselineSamples: z.number().int(),
  liveSamples: z.number().int(),
  features: z.array(DriftFeatureMetricSchema),
  recommendation: z.string()
});
export type DriftReport = z.infer<typeof DriftReportSchema>;

export const AdversarialAttackTypeSchema = z.enum([
  'HOMOGLYPH',
  'KEYWORD_STUFFING',
  'SUBDOMAIN_PACKING',
  'TLD_MASQUERADE',
  'LENGTH_INFLATION',
  'ENCODING_TRICK'
]);
export type AdversarialAttackType = z.infer<typeof AdversarialAttackTypeSchema>;

export const AdversarialAttackResultSchema = z.object({
  attackType: AdversarialAttackTypeSchema,
  originalUrl: z.string(),
  perturbedUrl: z.string(),
  originalScore: z.number().min(0).max(100),
  perturbedScore: z.number().min(0).max(100),
  evaded: z.boolean(),
  scoreDiff: z.number()
});
export type AdversarialAttackResult = z.infer<typeof AdversarialAttackResultSchema>;

export const AdversarialEvaluationReportSchema = z.object({
  testedAt: z.string(),
  totalTests: z.number().int(),
  evasionRate: z.number().min(0).max(1),
  overallRobustnessScore: z.number().min(0).max(100),
  results: z.array(AdversarialAttackResultSchema),
  hardeningStatus: z.enum(['ROBUST', 'VULNERABLE', 'CRITICAL_DEFICIT'])
});
export type AdversarialEvaluationReport = z.infer<typeof AdversarialEvaluationReportSchema>;

// ============================================================================
// Milestone 8: Enterprise SIEM/SOAR, Webhooks, Case Management & Email Ingestion
// ============================================================================

export const SIEMFormatSchema = z.enum([
  'CEF',
  'LEEF',
  'SYSLOG_RFC5424',
  'SENTINEL_JSON',
  'SPLUNK_HEC'
]);
export type SIEMFormat = z.infer<typeof SIEMFormatSchema>;

export const SIEMExportRequestSchema = z.object({
  format: SIEMFormatSchema,
  analysisIds: z.array(z.string()).optional(),
  campaignIds: z.array(z.string()).optional(),
  includeRawPayload: z.boolean().optional().default(false)
});
export type SIEMExportRequest = z.infer<typeof SIEMExportRequestSchema>;

export const SIEMExportResultSchema = z.object({
  format: SIEMFormatSchema,
  generatedAt: z.string(),
  eventCount: z.number().int().min(0),
  formattedOutput: z.string(),
  contentType: z.string()
});
export type SIEMExportResult = z.infer<typeof SIEMExportResultSchema>;

export const WebhookChannelTypeSchema = z.enum([
  'SLACK',
  'TEAMS',
  'DISCORD',
  'GENERIC_HTTP',
  'PAGERDUTY'
]);
export type WebhookChannelType = z.infer<typeof WebhookChannelTypeSchema>;

export const WebhookConfigSchema = z.object({
  id: z.string(),
  name: z.string(),
  url: z.string().url(),
  channelType: WebhookChannelTypeSchema,
  secretKey: z.string().optional().nullable(),
  minSeverity: RiskLevelSchema.default('HIGH'),
  events: z.array(z.string()).default(['CRITICAL_THREAT_DETECTED', 'CAMPAIGN_CLUSTERED', 'CASE_CREATED']),
  enabled: z.boolean().default(true),
  createdAt: z.string(),
  lastTriggeredAt: z.string().optional().nullable()
});
export type WebhookConfig = z.infer<typeof WebhookConfigSchema>;

export const CreateWebhookRequestSchema = z.object({
  name: z.string().min(2).max(100),
  url: z.string().url(),
  channelType: WebhookChannelTypeSchema,
  secretKey: z.string().optional(),
  minSeverity: RiskLevelSchema.optional().default('HIGH'),
  events: z.array(z.string()).optional(),
  enabled: z.boolean().optional().default(true)
});
export type CreateWebhookRequest = z.infer<typeof CreateWebhookRequestSchema>;

export const WebhookDeliveryLogSchema = z.object({
  id: z.string(),
  webhookId: z.string(),
  webhookName: z.string(),
  channelType: WebhookChannelTypeSchema,
  event: z.string(),
  statusCode: z.number().int().optional().nullable(),
  success: z.boolean(),
  error: z.string().optional().nullable(),
  payloadSummary: z.string(),
  timestamp: z.string()
});
export type WebhookDeliveryLog = z.infer<typeof WebhookDeliveryLogSchema>;

export const CaseStatusSchema = z.enum([
  'OPEN',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
  'FALSE_POSITIVE'
]);
export type CaseStatus = z.infer<typeof CaseStatusSchema>;

export const CaseSeveritySchema = z.enum([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW'
]);
export type CaseSeverity = z.infer<typeof CaseSeveritySchema>;

export const CaseTimelineEventSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  actor: z.string(),
  action: z.string(),
  details: z.string()
});
export type CaseTimelineEvent = z.infer<typeof CaseTimelineEventSchema>;

export const RemediationTypeSchema = z.enum([
  'DNS_SINKHOLE',
  'FIREWALL_BLOCK',
  'TAKEDOWN_NOTICE',
  'DOMAIN_REGISTRAR_REPORT',
  'EDR_ISOLATE'
]);
export type RemediationType = z.infer<typeof RemediationTypeSchema>;

export const RemediationResultSchema = z.object({
  actionType: RemediationTypeSchema,
  target: z.string(),
  generatedArtifact: z.string(),
  instructions: z.string(),
  executedAt: z.string(),
  status: z.enum(['GENERATED', 'APPLIED', 'FAILED'])
});
export type RemediationResult = z.infer<typeof RemediationResultSchema>;

export const SOCCaseSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  status: CaseStatusSchema,
  severity: CaseSeveritySchema,
  assignedAnalyst: z.string().optional().nullable(),
  targetUrl: z.string().optional().nullable(),
  targetDomain: z.string().optional().nullable(),
  linkedAnalysisId: z.string().optional().nullable(),
  linkedCampaignId: z.string().optional().nullable(),
  iocs: z.object({
    domains: z.array(z.string()).default([]),
    ips: z.array(z.string()).default([]),
    urls: z.array(z.string()).default([]),
    hashes: z.array(z.string()).default([])
  }).default({ domains: [], ips: [], urls: [], hashes: [] }),
  timeline: z.array(CaseTimelineEventSchema).default([]),
  notes: z.array(z.object({
    id: z.string(),
    author: z.string(),
    text: z.string(),
    timestamp: z.string()
  })).default([]),
  remediationActions: z.array(RemediationResultSchema).default([]),
  createdAt: z.string(),
  updatedAt: z.string(),
  closedAt: z.string().optional().nullable()
});
export type SOCCase = z.infer<typeof SOCCaseSchema>;

export const CreateCaseRequestSchema = z.object({
  title: z.string().min(3).max(200),
  description: z.string().min(5),
  severity: CaseSeveritySchema.default('HIGH'),
  targetUrl: z.string().optional(),
  targetDomain: z.string().optional(),
  linkedAnalysisId: z.string().optional(),
  linkedCampaignId: z.string().optional(),
  assignedAnalyst: z.string().optional()
});
export type CreateCaseRequest = z.infer<typeof CreateCaseRequestSchema>;

export const UpdateCaseRequestSchema = z.object({
  status: CaseStatusSchema.optional(),
  severity: CaseSeveritySchema.optional(),
  assignedAnalyst: z.string().optional(),
  note: z.string().optional()
});
export type UpdateCaseRequest = z.infer<typeof UpdateCaseRequestSchema>;

export const ExtractedIOCSchema = z.object({
  type: z.enum(['URL', 'DOMAIN', 'IP', 'EMAIL', 'HASH_MD5', 'HASH_SHA256']),
  value: z.string(),
  context: z.string().optional(),
  riskScore: z.number().min(0).max(100).optional(),
  isMalicious: z.boolean().default(false)
});
export type ExtractedIOC = z.infer<typeof ExtractedIOCSchema>;

export const EmailHeaderIntelligenceSchema = z.object({
  from: z.string(),
  replyTo: z.string().optional().nullable(),
  returnPath: z.string().optional().nullable(),
  subject: z.string(),
  date: z.string().optional().nullable(),
  spfStatus: z.enum(['PASS', 'FAIL', 'SOFTFAIL', 'NEUTRAL', 'NONE']).default('NONE'),
  dkimStatus: z.enum(['PASS', 'FAIL', 'NONE']).default('NONE'),
  dmarcStatus: z.enum(['PASS', 'FAIL', 'NONE']).default('NONE'),
  isSpoofed: z.boolean().default(false),
  sendingIp: z.string().optional().nullable()
});
export type EmailHeaderIntelligence = z.infer<typeof EmailHeaderIntelligenceSchema>;

export const EmailAnalysisRequestSchema = z.object({
  rawEmlText: z.string().min(10, 'Email raw text or RFC 822 format is required'),
  evaluateExtractedUrls: z.boolean().optional().default(true)
});
export type EmailAnalysisRequest = z.infer<typeof EmailAnalysisRequestSchema>;

export const EmailAnalysisResultSchema = z.object({
  analysisId: z.string(),
  headers: EmailHeaderIntelligenceSchema,
  totalUrlsExtracted: z.number().int().min(0),
  totalIocsExtracted: z.number().int().min(0),
  extractedIocs: z.array(ExtractedIOCSchema),
  analyzedUrls: z.array(AnalysisSummarySchema).default([]),
  phishingScore: z.number().min(0).max(100),
  verdict: ThreatVerdictSchema,
  riskLevel: RiskLevelSchema,
  evidenceReasons: z.array(z.string()),
  analyzedAt: z.string()
});
export type EmailAnalysisResult = z.infer<typeof EmailAnalysisResultSchema>;

export const RawIOCExtractionRequestSchema = z.object({
  rawText: z.string().min(5)
});
export type RawIOCExtractionRequest = z.infer<typeof RawIOCExtractionRequestSchema>;

export const RawIOCExtractionResultSchema = z.object({
  totalExtracted: z.number().int(),
  urls: z.array(z.string()),
  domains: z.array(z.string()),
  ips: z.array(z.string()),
  emails: z.array(z.string()),
  hashes: z.array(z.string())
});
export type RawIOCExtractionResult = z.infer<typeof RawIOCExtractionResultSchema>;

// ============================================================================
// Milestone 9: Governance, Calibration, Audit Logging & Feed Synchronization
// ============================================================================

export const LayerWeightsSchema = z.object({
  url: z.number().min(0).max(1).default(0.15),
  domain: z.number().min(0).max(1).default(0.10),
  dns: z.number().min(0).max(1).default(0.08),
  tls: z.number().min(0).max(1).default(0.07),
  reputation: z.number().min(0).max(1).default(0.20),
  ml: z.number().min(0).max(1).default(0.15),
  content: z.number().min(0).max(1).default(0.15),
  brand: z.number().min(0).max(1).default(0.10)
});
export type LayerWeights = z.infer<typeof LayerWeightsSchema>;

export const RiskThresholdsSchema = z.object({
  safeMax: z.number().min(10).max(50).default(35),
  suspiciousMax: z.number().min(51).max(85).default(70)
});
export type RiskThresholds = z.infer<typeof RiskThresholdsSchema>;

export const ReputationProviderConfigSchema = z.object({
  urlhausEnabled: z.boolean().default(true),
  phishTankEnabled: z.boolean().default(true),
  virusTotalEnabled: z.boolean().default(false)
});
export type ReputationProviderConfig = z.infer<typeof ReputationProviderConfigSchema>;

export const SystemConfigSchema = z.object({
  weights: LayerWeightsSchema,
  thresholds: RiskThresholdsSchema,
  providers: ReputationProviderConfigSchema,
  whitelistedDomains: z.array(z.string()).default([]),
  autoRemediateCritical: z.boolean().default(false),
  feedSyncIntervalMinutes: z.number().int().min(5).max(1440).default(60),
  updatedAt: z.string(),
  updatedBy: z.string()
});
export type SystemConfig = z.infer<typeof SystemConfigSchema>;

export const UpdateSystemConfigRequestSchema = z.object({
  weights: LayerWeightsSchema.partial().optional(),
  thresholds: RiskThresholdsSchema.partial().optional(),
  providers: ReputationProviderConfigSchema.partial().optional(),
  whitelistedDomains: z.array(z.string()).optional(),
  autoRemediateCritical: z.boolean().optional(),
  feedSyncIntervalMinutes: z.number().int().min(5).max(1440).optional()
});
export type UpdateSystemConfigRequest = z.infer<typeof UpdateSystemConfigRequestSchema>;

export const ApiKeyItemSchema = z.object({
  id: z.string(),
  name: z.string(),
  keyPrefix: z.string(),
  role: z.enum(['USER', 'ANALYST', 'ADMIN']),
  createdAt: z.string(),
  lastUsedAt: z.string().optional().nullable(),
  expiresAt: z.string().optional().nullable(),
  status: z.enum(['ACTIVE', 'REVOKED'])
});
export type ApiKeyItem = z.infer<typeof ApiKeyItemSchema>;

export const CreateApiKeyRequestSchema = z.object({
  name: z.string().min(2).max(100),
  role: z.enum(['USER', 'ANALYST', 'ADMIN']).default('ANALYST'),
  expiresInDays: z.number().int().min(1).max(365).optional()
});
export type CreateApiKeyRequest = z.infer<typeof CreateApiKeyRequestSchema>;

export const CreateApiKeyResponseSchema = z.object({
  apiKey: ApiKeyItemSchema,
  secretToken: z.string()
});
export type CreateApiKeyResponse = z.infer<typeof CreateApiKeyResponseSchema>;

export const AuditLogCategorySchema = z.enum([
  'AUTH',
  'ANALYSIS',
  'CASE',
  'REMEDIATION',
  'CONFIG',
  'THREAT_FEED',
  'MLOPS',
  'SECURITY'
]);
export type AuditLogCategory = z.infer<typeof AuditLogCategorySchema>;

export const AuditLogSeveritySchema = z.enum([
  'INFO',
  'WARNING',
  'CRITICAL'
]);
export type AuditLogSeverity = z.infer<typeof AuditLogSeveritySchema>;

export const AuditLogEntrySchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  actor: z.string(),
  action: z.string(),
  category: AuditLogCategorySchema,
  severity: AuditLogSeveritySchema,
  target: z.string().optional().nullable(),
  details: z.string(),
  ipAddress: z.string().optional().nullable()
});
export type AuditLogEntry = z.infer<typeof AuditLogEntrySchema>;

export const ThreatFeedSourceSchema = z.enum([
  'URLHAUS',
  'OPENPHISH',
  'PHISHTANK',
  'CISA_KEV'
]);
export type ThreatFeedSource = z.infer<typeof ThreatFeedSourceSchema>;

export const ThreatFeedStatusSchema = z.object({
  id: z.string(),
  name: z.string(),
  source: ThreatFeedSourceSchema,
  enabled: z.boolean(),
  iocCount: z.number().int(),
  lastSyncStatus: z.enum(['SUCCESS', 'RUNNING', 'FAILED', 'NEVER']),
  lastSyncAt: z.string().optional().nullable(),
  errorMessage: z.string().optional().nullable()
});
export type ThreatFeedStatus = z.infer<typeof ThreatFeedStatusSchema>;

export const ThreatFeedSyncResultSchema = z.object({
  source: ThreatFeedSourceSchema,
  syncDurationMs: z.number().int(),
  totalFetched: z.number().int(),
  newIocsAdded: z.number().int(),
  duplicatesSkipped: z.number().int(),
  status: z.enum(['SUCCESS', 'FAILED']),
  syncedAt: z.string()
});
export type ThreatFeedSyncResult = z.infer<typeof ThreatFeedSyncResultSchema>;

// ============================================================================
// Milestone 10: Threat Simulation Lab & Red Team Attack Replay
// ============================================================================

export const AttackVectorTypeSchema = z.enum([
  'SPEAR_PHISH_BRAND_IMPERSONATION',
  'UNICODE_HOMOGLYPH_PUNYCODE',
  'SUBDOMAIN_BRAND_PACKING',
  'COMBOSQUATTING_LOOKALIKE',
  'CREDENTIAL_HARVEST_CROSS_ORIGIN',
  'FAST_FLUX_DNS_EVASION',
  'SSRF_METADATA_PROBE',
  'SOCIAL_ENGINEERING_URGENCY',
  'PERCENT_ENCODING_HEX_OBFUSCATION',
  'SHORTENER_REDIRECT_CHAIN',
  'EXPIRED_SELFSIGNED_TLS',
  'DEFANGED_RAW_IOC_EVASION'
]);
export type AttackVectorType = z.infer<typeof AttackVectorTypeSchema>;

export const AttackScenarioPresetSchema = z.object({
  id: z.string(),
  name: z.string(),
  category: z.string(),
  description: z.string(),
  targetUrl: z.string(),
  targetBrand: z.string().optional().nullable(),
  techniques: z.array(z.string()),
  expectedRiskLevel: RiskLevelSchema,
  expectedVerdict: ThreatVerdictSchema,
  layerTriggers: z.array(z.string())
});
export type AttackScenarioPreset = z.infer<typeof AttackScenarioPresetSchema>;

export const AttackSimulationRequestSchema = z.object({
  presetId: z.string().optional(),
  targetUrl: z.string().min(3),
  targetBrand: z.string().optional(),
  vectorType: AttackVectorTypeSchema,
  simulateBrowser: z.boolean().optional(),
  customPayload: z.record(z.any()).optional()
});
export type AttackSimulationRequest = z.infer<typeof AttackSimulationRequestSchema>;

export const LayerSimulationStepSchema = z.object({
  layer: z.string(),
  status: z.string(),
  score: z.number().min(0).max(100),
  weight: z.number().min(0).max(1),
  weightedScore: z.number(),
  keyFinding: z.string(),
  evidenceCount: z.number().int(),
  isOverrideTriggered: z.boolean().default(false)
});
export type LayerSimulationStep = z.infer<typeof LayerSimulationStepSchema>;

export const AttackSimulationResultSchema = z.object({
  simulationId: z.string(),
  scenarioName: z.string(),
  targetUrl: z.string(),
  vectorType: AttackVectorTypeSchema,
  targetBrand: z.string().optional().nullable(),
  totalRiskScore: z.number().min(0).max(100),
  verdict: ThreatVerdictSchema,
  riskLevel: RiskLevelSchema,
  isMitigated: z.boolean(),
  zeroTrustHolding: z.boolean(),
  layerSteps: z.array(LayerSimulationStepSchema),
  generatedEvidence: z.array(EvidenceItemSchema),
  remediationRecommendations: z.array(z.string()),
  executionDurationMs: z.number().int(),
  simulatedAt: z.string()
});
export type AttackSimulationResult = z.infer<typeof AttackSimulationResultSchema>;

export const DefenseBenchmarkReportSchema = z.object({
  benchmarkId: z.string(),
  totalScenariosTested: z.number().int(),
  successfulMitigations: z.number().int(),
  evasionCount: z.number().int(),
  mitigationRatePercent: z.number().min(0).max(100),
  meanLatencyMs: z.number(),
  zeroTrustInvariantIntegrity: z.number().min(0).max(100),
  vectorBreakdown: z.array(z.object({
    vectorType: AttackVectorTypeSchema,
    total: z.number().int(),
    mitigated: z.number().int(),
    avgRiskScore: z.number()
  })),
  testedAt: z.string()
});
export type DefenseBenchmarkReport = z.infer<typeof DefenseBenchmarkReportSchema>;

// ============================================================================
// Milestone 12: Takedown Dispatcher, Team Workspaces & Executive Intelligence
// ============================================================================

export const TakedownNoticeTypeSchema = z.enum([
  'RFC2142_ABUSE_NOTICE',
  'ICANN_URS_COMPLAINT',
  'DMCA_512C_TAKEDOWN',
  'TRADEMARK_INFRINGEMENT',
  'REGISTRAR_SUSPENSION_REQUEST'
]);
export type TakedownNoticeType = z.infer<typeof TakedownNoticeTypeSchema>;

export const TakedownStatusSchema = z.enum([
  'DRAFTED',
  'PENDING_APPROVAL',
  'DISPATCHED',
  'ACKNOWLEDGED',
  'DOMAIN_SUSPENDED',
  'REJECTED'
]);
export type TakedownStatus = z.infer<typeof TakedownStatusSchema>;

export const TakedownNoticeSchema = z.object({
  id: z.string(),
  targetUrl: z.string(),
  targetDomain: z.string(),
  targetBrand: z.string().optional().nullable(),
  noticeType: TakedownNoticeTypeSchema,
  status: TakedownStatusSchema,
  recipientEmail: z.string().email(),
  recipientEntity: z.string(),
  subject: z.string(),
  bodyText: z.string(),
  evidenceSummary: z.array(z.string()),
  trackingNumber: z.string(),
  submittedBy: z.string(),
  dispatchedAt: z.string().optional().nullable(),
  resolvedAt: z.string().optional().nullable(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type TakedownNotice = z.infer<typeof TakedownNoticeSchema>;

export const CreateTakedownRequestSchema = z.object({
  targetUrl: z.string().min(3),
  targetBrand: z.string().optional(),
  noticeType: TakedownNoticeTypeSchema.default('RFC2142_ABUSE_NOTICE'),
  customNotes: z.string().optional(),
  autoDispatch: z.boolean().optional().default(false)
});
export type CreateTakedownRequest = z.infer<typeof CreateTakedownRequestSchema>;

export const OrganizationRoleSchema = z.enum([
  'OWNER',
  'SECURITY_ADMIN',
  'SOC_ANALYST',
  'AUDITOR',
  'VIEWER'
]);
export type OrganizationRole = z.infer<typeof OrganizationRoleSchema>;

export const TeamMemberSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string().email(),
  role: OrganizationRoleSchema,
  joinedAt: z.string(),
  lastActiveAt: z.string()
});
export type TeamMember = z.infer<typeof TeamMemberSchema>;

export const OrganizationWorkspaceSchema = z.object({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  plan: z.enum(['COMMUNITY', 'ENTERPRISE_SOC', 'GOVERNMENT_DEFENSE']),
  memberCount: z.number().int(),
  monthlyScanQuota: z.number().int(),
  usedScansThisMonth: z.number().int(),
  members: z.array(TeamMemberSchema),
  securityPolicy: z.object({
    mfaEnforced: z.boolean(),
    ipAllowlist: z.array(z.string()),
    autoSinkholingEnabled: z.boolean(),
    retentionDays: z.number().int()
  }),
  createdAt: z.string()
});
export type OrganizationWorkspace = z.infer<typeof OrganizationWorkspaceSchema>;

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
export type ExecutiveThreatReport = z.infer<typeof ExecutiveThreatReportSchema>;

// ============================================================================
// Milestone 13: SOAR Playbooks, Threat Hunting & TAXII/MISP Connectors
// ============================================================================

export const PlaybookTriggerTypeSchema = z.enum([
  'ON_PHISHING_DETECTED',
  'ON_HIGH_SEVERITY_INCIDENT',
  'ON_ZERO_DAY_DISCOVERY',
  'ON_BRAND_IMPERSONATION',
  'ON_MANUAL_TRIGGER'
]);
export type PlaybookTriggerType = z.infer<typeof PlaybookTriggerTypeSchema>;

export const PlaybookActionTypeSchema = z.enum([
  'BLOCK_DNS_SINKHOLE',
  'DISPATCH_RFC2142_TAKEDOWN',
  'CREATE_SOC_CASE',
  'NOTIFY_WEBHOOK',
  'ISOLATE_ENDPOINT_IOC',
  'TRIGGER_EMAIL_QUARANTINE'
]);
export type PlaybookActionType = z.infer<typeof PlaybookActionTypeSchema>;

export const PlaybookStepStatusSchema = z.enum([
  'PENDING',
  'RUNNING',
  'COMPLETED',
  'SKIPPED',
  'FAILED'
]);
export type PlaybookStepStatus = z.infer<typeof PlaybookStepStatusSchema>;

export const PlaybookStepSchema = z.object({
  id: z.string(),
  name: z.string(),
  actionType: PlaybookActionTypeSchema,
  parameters: z.record(z.any()).default({}),
  status: PlaybookStepStatusSchema.default('PENDING'),
  output: z.string().optional().nullable(),
  executionDurationMs: z.number().optional().nullable()
});
export type PlaybookStep = z.infer<typeof PlaybookStepSchema>;

export const PlaybookDefinitionSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  triggerType: PlaybookTriggerTypeSchema,
  enabled: z.boolean().default(true),
  conditions: z.object({
    minRiskScore: z.number().min(0).max(100).default(60),
    targetedBrands: z.array(z.string()).default([]),
    requiredVerdict: ThreatVerdictSchema.optional().nullable(),
    requireConfidence: z.number().min(0).max(1).default(0.7)
  }),
  steps: z.array(PlaybookStepSchema),
  executionCount: z.number().int().default(0),
  lastExecutedAt: z.string().optional().nullable(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type PlaybookDefinition = z.infer<typeof PlaybookDefinitionSchema>;

export const PlaybookExecutionRunSchema = z.object({
  id: z.string(),
  playbookId: z.string(),
  playbookName: z.string(),
  triggerSource: z.string(),
  triggeredBy: z.string(),
  status: z.enum(['RUNNING', 'SUCCESS', 'PARTIAL', 'FAILED']),
  targetUrl: z.string(),
  targetDomain: z.string(),
  steps: z.array(PlaybookStepSchema),
  logs: z.array(z.string()),
  startedAt: z.string(),
  completedAt: z.string().optional().nullable()
});
export type PlaybookExecutionRun = z.infer<typeof PlaybookExecutionRunSchema>;

export const CreatePlaybookRequestSchema = z.object({
  name: z.string().min(2),
  description: z.string().min(5),
  triggerType: PlaybookTriggerTypeSchema,
  enabled: z.boolean().optional().default(true),
  conditions: z.object({
    minRiskScore: z.number().min(0).max(100).optional().default(60),
    targetedBrands: z.array(z.string()).optional().default([]),
    requiredVerdict: ThreatVerdictSchema.optional().nullable(),
    requireConfidence: z.number().min(0).max(1).optional().default(0.7)
  }).optional(),
  steps: z.array(PlaybookStepSchema.omit({ status: true, output: true, executionDurationMs: true }))
});
export type CreatePlaybookRequest = z.infer<typeof CreatePlaybookRequestSchema>;

export const TriggerPlaybookRequestSchema = z.object({
  playbookId: z.string(),
  targetUrl: z.string().min(3),
  targetBrand: z.string().optional(),
  riskScore: z.number().optional().default(85),
  verdict: ThreatVerdictSchema.optional().default('PHISHING'),
  customPayload: z.record(z.any()).optional()
});
export type TriggerPlaybookRequest = z.infer<typeof TriggerPlaybookRequestSchema>;

// Threat Hunting & Forensic Replay Schemas
export const ForensicArtifactSchema = z.object({
  id: z.string(),
  targetUrl: z.string(),
  domain: z.string(),
  harArchive: z.object({
    totalRequests: z.number().int(),
    compressedSizeBytes: z.number().int(),
    entriesCount: z.number().int(),
    sampleHttpEntries: z.array(z.object({
      url: z.string(),
      method: z.string(),
      status: z.number().int(),
      mimeType: z.string(),
      timeMs: z.number()
    }))
  }),
  tlsCertificateChain: z.array(z.object({
    subject: z.string(),
    issuer: z.string(),
    validFrom: z.string(),
    validTo: z.string(),
    fingerprintSha256: z.string()
  })),
  domMutations: z.array(z.string()),
  dnsResolutionHistory: z.array(z.object({
    recordType: z.string(),
    value: z.string(),
    ttl: z.number().int(),
    firstSeen: z.string()
  })),
  liveHttpHeaders: z.record(z.string()),
  rawHtmlPreview: z.string(),
  createdAt: z.string()
});
export type ForensicArtifact = z.infer<typeof ForensicArtifactSchema>;

export const ThreatHuntQueryTypeSchema = z.enum([
  'DOMAIN_REGEX',
  'IP_CIDR',
  'ASN_LOOKUP',
  'HASH_SHA256',
  'BRAND_NAME',
  'JA3_FINGERPRINT'
]);
export type ThreatHuntQueryType = z.infer<typeof ThreatHuntQueryTypeSchema>;

export const ThreatHuntQuerySchema = z.object({
  queryType: ThreatHuntQueryTypeSchema,
  queryValue: z.string().min(1),
  timeRange: z.string().optional().default('All Time')
});
export type ThreatHuntQuery = z.infer<typeof ThreatHuntQuerySchema>;

export const ThreatHuntResultSchema = z.object({
  query: ThreatHuntQuerySchema,
  totalMatches: z.number().int(),
  matches: z.array(z.object({
    id: z.string(),
    indicator: z.string(),
    indicatorType: z.string(),
    verdict: ThreatVerdictSchema,
    riskScore: z.number(),
    firstSeen: z.string(),
    lastSeen: z.string(),
    campaignTag: z.string().optional().nullable(),
    sourceLayer: z.string()
  })),
  relatedCampaigns: z.array(z.string()),
  activeSinkholes: z.array(z.string()),
  pivotSuggestions: z.array(z.string())
});
export type ThreatHuntResult = z.infer<typeof ThreatHuntResultSchema>;

// Threat Intel Platform Connectors (TAXII 2.1, MISP, AlienVault)
export const ThreatConnectorTypeSchema = z.enum([
  'TAXII21_FEED',
  'MISP_COMMUNITY',
  'ALIENVAULT_OTX',
  'ABUSE_IPDB'
]);
export type ThreatConnectorType = z.infer<typeof ThreatConnectorTypeSchema>;

export const ThreatConnectorStatusSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: ThreatConnectorTypeSchema,
  endpointUrl: z.string(),
  enabled: z.boolean(),
  pollIntervalMinutes: z.number().int(),
  lastPollAt: z.string().optional().nullable(),
  totalIocsIngested: z.number().int(),
  status: z.enum(['HEALTHY', 'SYNCING', 'ERROR'])
});
export type ThreatConnectorStatus = z.infer<typeof ThreatConnectorStatusSchema>;

// ============================================================================
// Milestone 14: AI SOC Co-Pilot, Canary Deception & EASM Schemas
// ============================================================================

// 1. AI SOC Co-Pilot Schemas
export const CopilotSessionTypeSchema = z.enum([
  'GENERAL',
  'TRIAGE',
  'HUNTING_COMPILER',
  'INCIDENT_ANALYSIS',
  'REMEDIATION'
]);
export type CopilotSessionType = z.infer<typeof CopilotSessionTypeSchema>;

export const CopilotSuggestedActionSchema = z.object({
  id: z.string(),
  label: z.string(),
  actionType: z.enum(['TRIGGER_PLAYBOOK', 'RUN_HUNT', 'CREATE_TAKEDOWN', 'DEPLOY_CANARY', 'ISOLATE_HOST']),
  payload: z.record(z.any())
});
export type CopilotSuggestedAction = z.infer<typeof CopilotSuggestedActionSchema>;

export const CopilotReasoningStepSchema = z.object({
  stepNumber: z.number().int(),
  stage: z.string(),
  observation: z.string(),
  verdict: z.string()
});
export type CopilotReasoningStep = z.infer<typeof CopilotReasoningStepSchema>;

export const CopilotChatRequestSchema = z.object({
  prompt: z.string().min(1),
  sessionType: CopilotSessionTypeSchema.optional().default('GENERAL'),
  context: z.object({
    analysisId: z.string().optional(),
    domain: z.string().optional(),
    targetUrl: z.string().optional(),
    verdict: ThreatVerdictSchema.optional(),
    riskScore: z.number().optional(),
    brand: z.string().optional(),
    evidenceKeys: z.array(z.string()).optional()
  }).optional(),
  history: z.array(z.object({
    sender: z.enum(['USER', 'COPILOT']),
    message: z.string(),
    timestamp: z.string()
  })).optional().default([])
});
export type CopilotChatRequest = z.infer<typeof CopilotChatRequestSchema>;

export const CopilotChatResponseSchema = z.object({
  id: z.string(),
  reply: z.string(),
  sessionType: CopilotSessionTypeSchema,
  reasoningSteps: z.array(CopilotReasoningStepSchema),
  suggestedActions: z.array(CopilotSuggestedActionSchema),
  generatedArtifacts: z.object({
    huntQuery: z.string().optional(),
    snortRule: z.string().optional(),
    siemKqlQuery: z.string().optional(),
    takedownDraft: z.string().optional(),
    dnsRpzEntry: z.string().optional()
  }),
  mitreTechniques: z.array(z.object({
    id: z.string(),
    name: z.string(),
    tactic: z.string()
  })),
  citations: z.array(z.string()),
  tokensUsed: z.number().int(),
  createdAt: z.string()
});
export type CopilotChatResponse = z.infer<typeof CopilotChatResponseSchema>;

export const CopilotPromptTemplateSchema = z.object({
  id: z.string(),
  title: z.string(),
  category: z.string(),
  prompt: z.string(),
  description: z.string()
});
export type CopilotPromptTemplate = z.infer<typeof CopilotPromptTemplateSchema>;

// 2. Active Canary Deception Engine Schemas
export const CanaryTokenTypeSchema = z.enum([
  'HTTP_WEB_BUG',
  'DNS_TRIPWIRE',
  'DECOY_CREDENTIAL',
  'CLONED_LOGIN_BEACON',
  'FAKE_API_KEY'
]);
export type CanaryTokenType = z.infer<typeof CanaryTokenTypeSchema>;

export const CanaryTokenSchema = z.object({
  id: z.string(),
  name: z.string(),
  tokenType: CanaryTokenTypeSchema,
  tokenString: z.string(),
  targetDeployLocation: z.string(),
  triggeredCount: z.number().int().default(0),
  lastTriggeredAt: z.string().optional().nullable(),
  status: z.enum(['ACTIVE', 'DISABLED', 'REVOKED']).default('ACTIVE'),
  alertSeverity: EvidenceSeveritySchema.default('HIGH'),
  deploySnippet: z.string(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type CanaryToken = z.infer<typeof CanaryTokenSchema>;

export const CanaryTriggerEventSchema = z.object({
  id: z.string(),
  tokenId: z.string(),
  tokenName: z.string(),
  tokenType: CanaryTokenTypeSchema,
  triggeredAt: z.string(),
  sourceIp: z.string(),
  country: z.string(),
  city: z.string(),
  userAgent: z.string(),
  ja3Fingerprint: z.string().optional(),
  capturedHeaders: z.record(z.string()),
  capturedPayload: z.string().optional().nullable(),
  riskScore: z.number(),
  attackerIntent: z.string()
});
export type CanaryTriggerEvent = z.infer<typeof CanaryTriggerEventSchema>;

export const CreateCanaryTokenRequestSchema = z.object({
  name: z.string().min(2),
  tokenType: CanaryTokenTypeSchema,
  targetDeployLocation: z.string().min(2),
  alertSeverity: EvidenceSeveritySchema.optional().default('HIGH'),
  customNotes: z.string().optional()
});
export type CreateCanaryTokenRequest = z.infer<typeof CreateCanaryTokenRequestSchema>;

// 3. External Attack Surface Management (EASM) Schemas
export const AttackSurfaceAssetTypeSchema = z.enum([
  'DOMAIN',
  'SUBDOMAIN',
  'IP_ADDRESS',
  'SSL_CERTIFICATE',
  'BRAND_KEYWORD',
  'EXPOSED_SERVICE'
]);
export type AttackSurfaceAssetType = z.infer<typeof AttackSurfaceAssetTypeSchema>;

export const AttackSurfaceAssetSchema = z.object({
  id: z.string(),
  name: z.string(),
  assetType: AttackSurfaceAssetTypeSchema,
  targetValue: z.string(),
  riskLevel: RiskLevelSchema,
  status: z.enum(['MONITORED', 'SUSPICIOUS', 'ATTACKED', 'RESOLVED']).default('MONITORED'),
  discoverySource: z.enum(['CT_LOGS', 'DNS_BRUTEFORCE', 'WHOIS_REVERSE', 'DARK_WEB', 'MANUAL']),
  associatedBrands: z.array(z.string()),
  openPorts: z.array(z.number().int()),
  tlsExpiryDate: z.string().optional().nullable(),
  detectedThreatsCount: z.number().int().default(0),
  lastScannedAt: z.string(),
  createdAt: z.string()
});
export type AttackSurfaceAsset = z.infer<typeof AttackSurfaceAssetSchema>;

export const CTLogEntrySchema = z.object({
  id: z.string(),
  domain: z.string(),
  issuer: z.string(),
  sanNames: z.array(z.string()),
  loggedAt: z.string(),
  isTyposquat: z.boolean(),
  targetedBrand: z.string().optional().nullable(),
  riskScore: z.number(),
  autoQuarantined: z.boolean()
});
export type CTLogEntry = z.infer<typeof CTLogEntrySchema>;

export const CreateAttackSurfaceAssetRequestSchema = z.object({
  name: z.string().min(2),
  assetType: AttackSurfaceAssetTypeSchema,
  targetValue: z.string().min(2),
  associatedBrands: z.array(z.string()).optional().default([])
});
export type CreateAttackSurfaceAssetRequest = z.infer<typeof CreateAttackSurfaceAssetRequestSchema>;

// ============================================================================
// Milestone 15: Remote Browser Isolation (RBI), Tarpit & TAXII 2.1 Server
// ============================================================================

// 1. Remote Browser Isolation (RBI) Schemas
export const RBISessionStatusSchema = z.enum(['STARTING', 'RUNNING', 'TERMINATED', 'BLOCKED']);
export type RBISessionStatus = z.infer<typeof RBISessionStatusSchema>;

export const RBISecurityPolicySchema = z.object({
  blockWebSockets: z.boolean().default(true),
  blockWebRTC: z.boolean().default(true),
  blockClipboardWrite: z.boolean().default(true),
  blockFormSubmit: z.boolean().default(true),
  canvasRandomization: z.boolean().default(true),
  stripMaliciousScripts: z.boolean().default(true),
  enforceZeroTrustCSP: z.boolean().default(true)
});
export type RBISecurityPolicy = z.infer<typeof RBISecurityPolicySchema>;

export const RBIBrowserEventTypeSchema = z.enum([
  'NAVIGATE',
  'EVAL_BLOCKED',
  'KEYLOGGER_INTERCEPTED',
  'FORM_SUBMIT_BLOCKED',
  'CANVAS_PROBE_CLOAKED',
  'WEBSOCKET_BLOCKED',
  'CLIPBOARD_HIJACK_BLOCKED',
  'REDIRECT'
]);
export type RBIBrowserEventType = z.infer<typeof RBIBrowserEventTypeSchema>;

export const RBIBrowserEventSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  eventType: RBIBrowserEventTypeSchema,
  severity: EvidenceSeveritySchema,
  details: z.string(),
  sourceSnippet: z.string().optional()
});
export type RBIBrowserEvent = z.infer<typeof RBIBrowserEventSchema>;

export const RBISessionSchema = z.object({
  id: z.string(),
  targetUrl: z.string(),
  domain: z.string(),
  status: RBISessionStatusSchema,
  securityPolicy: RBISecurityPolicySchema,
  containerId: z.string(),
  sandboxResolution: z.string().default('1280x800'),
  liveEvents: z.array(RBIBrowserEventSchema),
  deWeaponizedHtml: z.string(),
  activeTabTitle: z.string(),
  startedAt: z.string(),
  terminatedAt: z.string().optional().nullable()
});
export type RBISession = z.infer<typeof RBISessionSchema>;

export const CreateRBISessionRequestSchema = z.object({
  targetUrl: z.string().min(3),
  securityPolicy: RBISecurityPolicySchema.partial().optional()
});
export type CreateRBISessionRequest = z.infer<typeof CreateRBISessionRequestSchema>;

// 2. Phishing Tarpit & Synthetic Credential Flooder Schemas
export const TarpitTaskStatusSchema = z.enum(['QUEUED', 'ACTIVE', 'PAUSED', 'COMPLETED', 'STOPPED']);
export type TarpitTaskStatus = z.infer<typeof TarpitTaskStatusSchema>;

export const PoisonedCredentialSchema = z.object({
  id: z.string(),
  username: z.string(),
  password: z.string(),
  otpCode: z.string(),
  canaryTag: z.string(),
  injectedAt: z.string(),
  submissionStatus: z.enum(['SENT', 'FAILED', 'RATE_LIMITED']),
  responseLatencyMs: z.number()
});
export type PoisonedCredential = z.infer<typeof PoisonedCredentialSchema>;

export const TarpitTaskSchema = z.object({
  id: z.string(),
  targetUrl: z.string(),
  targetFormAction: z.string(),
  status: TarpitTaskStatusSchema,
  concurrency: z.number().int().min(1).max(20).default(5),
  totalCredentialsInjected: z.number().int().default(0),
  targetExhaustionRate: z.number().min(0).max(100).default(0),
  meanAdversaryLatencyMs: z.number().default(0),
  adversaryStatusCode: z.number().int().default(200),
  poisonedCredentials: z.array(PoisonedCredentialSchema),
  startedAt: z.string(),
  stoppedAt: z.string().optional().nullable()
});
export type TarpitTask = z.infer<typeof TarpitTaskSchema>;

export const LaunchTarpitTaskRequestSchema = z.object({
  targetUrl: z.string().min(3),
  targetFormAction: z.string().min(1),
  concurrency: z.number().int().min(1).max(20).optional().default(5),
  credentialsCount: z.number().int().min(10).max(5000).optional().default(100),
  targetBrand: z.string().optional()
});
export type LaunchTarpitTaskRequest = z.infer<typeof LaunchTarpitTaskRequestSchema>;

// 3. STIX 2.1 & TAXII 2.1 Server Schemas
export const TAXIICollectionSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  canRead: z.boolean(),
  canWrite: z.boolean(),
  mediaTypes: z.array(z.string()),
  objectsCount: z.number().int()
});
export type TAXIICollection = z.infer<typeof TAXIICollectionSchema>;

export const TAXIIDiscoverySchema = z.object({
  title: z.string(),
  description: z.string(),
  contact: z.string(),
  defaultApiRoot: z.string(),
  apiRoots: z.array(z.string())
});
export type TAXIIDiscovery = z.infer<typeof TAXIIDiscoverySchema>;

// ============================================================================
// Milestone 16: AiTM Reverse Proxy Defense, Threat Intel Fusion & Compliance
// ============================================================================

// 1. Adversary-in-the-Middle (AiTM) Reverse Proxy Defense Schemas
export const AiTMThreatTypeSchema = z.enum([
  'EVILGINX_REVERSE_PROXY',
  'MODLISHKA_PROXY',
  'MURAENA_PROXY',
  'COOKIE_SESSION_INTERCEPT',
  'DOMAIN_BINDING_MISMATCH',
  'HEADER_INJECTION_ANOMALY'
]);
export type AiTMThreatType = z.infer<typeof AiTMThreatTypeSchema>;

export const AiTMProxyIndicatorSchema = z.object({
  type: z.string(),
  severity: EvidenceSeveritySchema,
  description: z.string(),
  detectedPattern: z.string()
});
export type AiTMProxyIndicator = z.infer<typeof AiTMProxyIndicatorSchema>;

export const AiTMSessionScanRequestSchema = z.object({
  targetUrl: z.string().min(3),
  headers: z.record(z.string()).optional(),
  cookiesPresent: z.array(z.string()).optional(),
  claimedHost: z.string().optional()
});
export type AiTMSessionScanRequest = z.infer<typeof AiTMSessionScanRequestSchema>;

export const AiTMSessionScanResultSchema = z.object({
  id: z.string(),
  targetUrl: z.string(),
  isAiTMProxy: z.boolean(),
  threatType: AiTMThreatTypeSchema.optional().nullable(),
  riskScore: z.number().min(0).max(100),
  indicators: z.array(AiTMProxyIndicatorSchema),
  recommendedAction: z.enum(['BLOCK_AND_INVALIDATE', 'ENFORCE_FIDO2_STEPUP', 'FLAG_SUSPICIOUS', 'ALLOW']),
  mitigationArtifact: z.string(),
  evaluatedAt: z.string()
});
export type AiTMSessionScanResult = z.infer<typeof AiTMSessionScanResultSchema>;

// 2. Threat Intelligence Fusion & Bayesian Half-Life Decay Schemas
export const ThreatFusionEntrySchema = z.object({
  id: z.string(),
  iocValue: z.string(),
  iocType: z.enum(['DOMAIN', 'IP', 'URL', 'HASH', 'ASN']),
  firstSeen: z.string(),
  lastSeen: z.string(),
  sourceFeeds: z.array(z.string()),
  baseScore: z.number().min(0).max(100),
  decayedScore: z.number().min(0).max(100),
  halfLifeHours: z.number(),
  confidence: z.number().min(0).max(1),
  status: z.enum(['ACTIVE', 'DECAYED', 'BENIGN'])
});
export type ThreatFusionEntry = z.infer<typeof ThreatFusionEntrySchema>;

export const BayesianDecayConfigSchema = z.object({
  defaultHalfLifeHours: z.number().default(48),
  fastFluxIpHalfLifeHours: z.number().default(24),
  domainHalfLifeHours: z.number().default(168),
  decayFloorScore: z.number().default(5)
});
export type BayesianDecayConfig = z.infer<typeof BayesianDecayConfigSchema>;

export const ThreatFusionScoreRequestSchema = z.object({
  iocValue: z.string().min(2),
  iocType: z.enum(['DOMAIN', 'IP', 'URL', 'HASH', 'ASN']),
  sourceFeeds: z.array(z.string()).optional(),
  customHalfLifeHours: z.number().optional()
});
export type ThreatFusionScoreRequest = z.infer<typeof ThreatFusionScoreRequestSchema>;

// 3. Enterprise Compliance & Posture Audit Schemas
export const ComplianceFrameworkSchema = z.enum([
  'NIST_CSF_2',
  'CIS_CONTROLS_V8',
  'SOC_2_TYPE_II',
  'ISO_27001'
]);
export type ComplianceFramework = z.infer<typeof ComplianceFrameworkSchema>;

export const ComplianceControlItemSchema = z.object({
  controlId: z.string(),
  controlName: z.string(),
  framework: ComplianceFrameworkSchema,
  status: z.enum(['PASSED', 'WARNING', 'FAIL']),
  evidenceDescription: z.string(),
  score: z.number().min(0).max(100)
});
export type ComplianceControlItem = z.infer<typeof ComplianceControlItemSchema>;

export const ComplianceAuditResultSchema = z.object({
  auditId: z.string(),
  auditedAt: z.string(),
  framework: ComplianceFrameworkSchema,
  overallCompliancePercent: z.number().min(0).max(100),
  totalControls: z.number(),
  passedControls: z.number(),
  controls: z.array(ComplianceControlItemSchema),
  executiveSummary: z.string()
});
export type ComplianceAuditResult = z.infer<typeof ComplianceAuditResultSchema>;

// ============================================================================
// Milestone 17: Multimodal Quishing Defense, Threat Actor Attribution & FAIR Cyber Risk
// ============================================================================

// 1. Quishing (QR Code Phishing) & Multimodal Defense
export const QRCodeMetadataSchema = z.object({
  detected: z.boolean(),
  format: z.string().default('QR_CODE'),
  payloadUrl: z.string(),
  errorCorrectionLevel: z.enum(['L', 'M', 'Q', 'H']).default('M'),
  isDynamicOrTracking: z.boolean().default(false)
});
export type QRCodeMetadata = z.infer<typeof QRCodeMetadataSchema>;

export const VisualLureItemSchema = z.object({
  text: z.string(),
  confidence: z.number().min(0).max(1),
  brandTargeted: z.string().optional(),
  urgencyCategory: z.enum([
    'CREDENTIAL_EXPIRY',
    'MFA_RESET',
    'ACCOUNT_SUSPENSION',
    'PAYMENT_FAIL',
    'GENERAL_LURE'
  ])
});
export type VisualLureItem = z.infer<typeof VisualLureItemSchema>;

export const QuishingScanRequestSchema = z.object({
  imageUrl: z.string().optional(),
  imageBase64: z.string().optional(),
  rawText: z.string().optional(),
  ocrExtract: z.boolean().default(true),
  deepScanPayload: z.boolean().default(true)
});
export type QuishingScanRequest = z.infer<typeof QuishingScanRequestSchema>;

export const QuishingScanResultSchema = z.object({
  scanId: z.string(),
  scannedAt: z.string(),
  qrDetected: z.boolean(),
  qrMetadata: QRCodeMetadataSchema.optional(),
  extractedUrls: z.array(z.string()),
  visualLures: z.array(VisualLureItemSchema),
  isQuishingAttack: z.boolean(),
  riskScore: z.number().min(0).max(100),
  verdict: z.enum(['SAFE', 'SUSPICIOUS', 'PHISHING']),
  recommendedAction: z.string(),
  mitigationPayload: z.object({
    fido2Enforced: z.boolean(),
    qrBlockedAtGateway: z.boolean(),
    snortRule: z.string().optional()
  }).optional()
});
export type QuishingScanResult = z.infer<typeof QuishingScanResultSchema>;

// 2. Adversary & Threat Actor Attribution Matrix
export const ThreatActorProfileSchema = z.object({
  actorId: z.string(),
  actorName: z.string(),
  aliases: z.array(z.string()),
  originCountry: z.string(),
  primaryTargets: z.array(z.string()),
  mitreAttckTTPs: z.array(z.string()),
  infrastructurePatterns: z.object({
    asns: z.array(z.string()),
    tlds: z.array(z.string()),
    registries: z.array(z.string())
  }),
  knownSignatures: z.array(z.string())
});
export type ThreatActorProfile = z.infer<typeof ThreatActorProfileSchema>;

export const AttributionMatchItemSchema = z.object({
  actorId: z.string(),
  actorName: z.string(),
  attributionConfidence: z.number().min(0).max(100),
  matchedTTPs: z.array(z.string()),
  matchedInfrastructure: z.array(z.string()),
  adversaryDiamondModel: z.object({
    adversary: z.string(),
    capability: z.string(),
    infrastructure: z.string(),
    victimology: z.string()
  })
});
export type AttributionMatchItem = z.infer<typeof AttributionMatchItemSchema>;

export const AttributionMatchResultSchema = z.object({
  queryId: z.string(),
  analyzedAt: z.string(),
  targetDomain: z.string(),
  topMatches: z.array(AttributionMatchItemSchema),
  attributionVerdict: z.string(),
  mitreHeatmap: z.record(z.string(), z.number())
});
export type AttributionMatchResult = z.infer<typeof AttributionMatchResultSchema>;

// 3. Quantitative Cyber Risk Quantification (FAIR Model)
export const FAIRRiskParamsSchema = z.object({
  annualPhishingAttempts: z.number().min(1).default(5000),
  susceptibilityRate: z.number().min(0).max(1).default(0.12),
  controlEffectiveness: z.number().min(0).max(1).default(0.85),
  averageEmployeeCount: z.number().min(1).default(500),
  costPerCompromisedCredential: z.number().min(100).default(4200),
  secondaryRegulatoryFineLikelihood: z.number().min(0).max(1).default(0.15),
  maxRegulatoryFine: z.number().min(0).default(2500000)
});
export type FAIRRiskParams = z.infer<typeof FAIRRiskParamsSchema>;

export const LossDistributionSchema = z.object({
  tenthPercentile: z.number(),
  fiftiethPercentile: z.number(),
  ninetiethPercentile: z.number(),
  expectedAnnualLoss: z.number()
});
export type LossDistribution = z.infer<typeof LossDistributionSchema>;

export const FAIRRiskAssessmentResultSchema = z.object({
  assessmentId: z.string(),
  calculatedAt: z.string(),
  lossEventFrequency: z.number(),
  vulnerabilityRatio: z.number(),
  primaryLossExpected: z.number(),
  secondaryLossExpected: z.number(),
  totalExpectedAnnualLoss: z.number(),
  annualLossMitigatedByPhishNetra: z.number(),
  defenseRoiMultiple: z.number(),
  lossDistribution: LossDistributionSchema,
  riskTier: z.enum(['CRITICAL', 'HIGH', 'ELEVATED', 'MODERATE', 'LOW'])
});
export type FAIRRiskAssessmentResult = z.infer<typeof FAIRRiskAssessmentResultSchema>;

// ============================================================================
// Milestone 18: Client Anti-Tamper SDK, Continuous Session Verification & MITRE D3FEND
// ============================================================================

// 1. Client-Side Anti-Tampering & DOM Cloaking Defense
export const ClientGuardConfigSchema = z.object({
  enableDevToolsTrap: z.boolean().default(true),
  enableMutationTrap: z.boolean().default(true),
  enableClickjackingTrap: z.boolean().default(true),
  enableWatermarking: z.boolean().default(true),
  reportingEndpoint: z.string().default('/api/client-defense/beacon'),
  targetDomain: z.string().min(2)
});
export type ClientGuardConfig = z.infer<typeof ClientGuardConfigSchema>;

export const ClientTamperEventSchema = z.object({
  eventId: z.string(),
  timestamp: z.string(),
  targetDomain: z.string(),
  tamperType: z.enum([
    'DEVTOOLS_OPENED',
    'DOM_OVERLAY_INJECTED',
    'CLICKJACKING_IFRAME_DETECTED',
    'SCRIPT_MODIFIED',
    'KEYLOGGER_INTERCEPTOR'
  ]),
  clientIp: z.string(),
  userAgent: z.string(),
  payloadDetails: z.record(z.string(), z.any()),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
});
export type ClientTamperEvent = z.infer<typeof ClientTamperEventSchema>;

export const ClientGuardScriptResultSchema = z.object({
  configId: z.string(),
  generatedAt: z.string(),
  targetDomain: z.string(),
  obfuscatedScript: z.string(),
  scriptIntegrityHash: z.string()
});
export type ClientGuardScriptResult = z.infer<typeof ClientGuardScriptResultSchema>;

// 2. Zero-Trust Continuous Session Verification & Impossible Travel Anomaly
export const SessionTelemetryProbeSchema = z.object({
  sessionId: z.string(),
  userEmail: z.string().email(),
  timestamp: z.string(),
  ipAddress: z.string(),
  geoCoordinates: z.object({
    latitude: z.number(),
    longitude: z.number(),
    country: z.string(),
    city: z.string()
  }),
  tlsJa3Fingerprint: z.string(),
  userAgent: z.string()
});
export type SessionTelemetryProbe = z.infer<typeof SessionTelemetryProbeSchema>;

export const ContinuousRiskAssessmentSchema = z.object({
  assessmentId: z.string(),
  sessionId: z.string(),
  userEmail: z.string(),
  evaluatedAt: z.string(),
  continuousRiskScore: z.number().min(0).max(100),
  anomaliesDetected: z.array(z.string()),
  impossibleTravelVelocityKmh: z.number().optional(),
  tlsDriftDetected: z.boolean(),
  deviceProfileMutated: z.boolean(),
  actionTaken: z.enum(['ALLOW', 'STEP_UP_CHALLENGE', 'TERMINATE_SESSION']),
  killSwitchDispatched: z.boolean()
});
export type ContinuousRiskAssessment = z.infer<typeof ContinuousRiskAssessmentSchema>;

// 3. MITRE D3FEND Defensive Countermeasure Matrix
export const D3FENDTacticSchema = z.enum([
  'MODEL',
  'HARDEN',
  'DETECT',
  'ISOLATE',
  'DECEIVE'
]);
export type D3FENDTactic = z.infer<typeof D3FENDTacticSchema>;

export const D3FENDTechniqueMappingSchema = z.object({
  d3fendId: z.string(),
  techniqueName: z.string(),
  tactic: D3FENDTacticSchema,
  phishNetraCapability: z.string(),
  coverageScore: z.number().min(0).max(100),
  verificationStatus: z.enum(['VERIFIED', 'PARTIAL', 'PLANNED'])
});
export type D3FENDTechniqueMapping = z.infer<typeof D3FENDTechniqueMappingSchema>;

export const D3FENDMatrixCoverageSchema = z.object({
  matrixId: z.string(),
  generatedAt: z.string(),
  totalTechniques: z.number(),
  verifiedTechniques: z.number(),
  overallDefensivePostureScore: z.number().min(0).max(100),
  tacticCoverage: z.record(z.string(), z.number()),
  techniques: z.array(D3FENDTechniqueMappingSchema)
});
export type D3FENDMatrixCoverage = z.infer<typeof D3FENDMatrixCoverageSchema>;

// ============================================================================
// Milestone 19: GenAI Adversarial Defense, Telecom Fusion & Digital Forensics
// ============================================================================

// 1. GenAI Phishing & Prompt Injection Defense
export const GenAIAnalysisRequestSchema = z.object({
  content: z.string().min(1),
  sourceChannel: z.enum(['EMAIL_BODY', 'WEB_PAGE_DOM', 'CHAT_PAYLOAD', 'SMS_TEXT']).default('EMAIL_BODY'),
  sanitizeContent: z.boolean().default(true),
  scanHiddenDom: z.boolean().default(true)
});
export type GenAIAnalysisRequest = z.infer<typeof GenAIAnalysisRequestSchema>;

export const GenAIAnalysisResultSchema = z.object({
  scanId: z.string(),
  scannedAt: z.string(),
  promptInjectionDetected: z.boolean(),
  injectionTechnique: z.enum([
    'INDIRECT_PROMPT_INJECTION',
    'JAILBREAK_ATTEMPT',
    'ZERO_WIDTH_STEGANOGRAPHY',
    'HIDDEN_CSS_PAYLOAD',
    'NONE'
  ]),
  syntheticLureLikelihood: z.number().min(0).max(100),
  perplexityScore: z.number(),
  detectedSignatures: z.array(z.string()),
  riskLevel: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']),
  neutralizedContent: z.string(),
  defenseAction: z.enum(['QUARANTINE', 'SANITIZE', 'ALLOW'])
});
export type GenAIAnalysisResult = z.infer<typeof GenAIAnalysisResultSchema>;

// 2. Telecom Multi-Vector Fusion (Smishing, Vishing & STIR/SHAKEN)
export const TelecomThreatProbeSchema = z.object({
  channel: z.enum(['SMS_SMISHING', 'VOIP_VISHING', 'MMS', 'CROSS_CHANNEL']),
  callerOrSenderId: z.string().min(3),
  messageOrTranscript: z.string(),
  stirShakenAttestation: z.enum(['A', 'B', 'C', 'UNATTESTED']).default('UNATTESTED'),
  originCarrier: z.string().optional(),
  originCountry: z.string().optional(),
  extractedUrls: z.array(z.string()).default([]),
  audioDurationSeconds: z.number().optional()
});
export type TelecomThreatProbe = z.infer<typeof TelecomThreatProbeSchema>;

export const TelecomThreatAssessmentSchema = z.object({
  assessmentId: z.string(),
  evaluatedAt: z.string(),
  channel: z.enum(['SMS_SMISHING', 'VOIP_VISHING', 'MMS', 'CROSS_CHANNEL']),
  callerOrSenderId: z.string(),
  stirShakenAttestation: z.enum(['A', 'B', 'C', 'UNATTESTED']),
  syntheticVoiceLikelihood: z.number().min(0).max(100),
  urgencySocialEngineeringScore: z.number().min(0).max(100),
  multiVectorConvergenceIndex: z.number().min(0).max(100),
  correlatedCampaignId: z.string().optional(),
  anomaliesDetected: z.array(z.string()),
  verdict: z.enum(['CRITICAL_CONVERGENCE', 'SUSPICIOUS', 'LEGITIMATE']),
  recommendedTelecomAction: z.enum(['CARRIER_BLOCK_DISPATCH', 'FLAG_SUSPICIOUS', 'ALLOW'])
});
export type TelecomThreatAssessment = z.infer<typeof TelecomThreatAssessmentSchema>;

// 3. Automated Digital Forensics & HAR Deep Packet Inspection (ADFA)
export const HAREntrySchema = z.object({
  id: z.string(),
  startedDateTime: z.string(),
  request: z.object({
    method: z.string(),
    url: z.string(),
    headers: z.array(z.object({ name: z.string(), value: z.string() })).default([]),
    queryString: z.array(z.object({ name: z.string(), value: z.string() })).default([]),
    postData: z.object({ mimeType: z.string(), text: z.string().optional() }).optional()
  }),
  response: z.object({
    status: z.number(),
    statusText: z.string(),
    headers: z.array(z.object({ name: z.string(), value: z.string() })).default([]),
    content: z.object({ size: z.number(), mimeType: z.string(), text: z.string().optional() }).optional()
  }),
  time: z.number().default(0)
});
export type HAREntry = z.infer<typeof HAREntrySchema>;

export const HARForensicIngestSchema = z.object({
  targetUrl: z.string(),
  capturedBy: z.string().default('PhishNetra Automated DPI Agent'),
  entries: z.array(HAREntrySchema),
  environmentDetails: z.record(z.string(), z.any()).optional().default({})
});
export type HARForensicIngest = z.infer<typeof HARForensicIngestSchema>;

export const HARForensicArtifactSchema = z.object({
  artifactId: z.string(),
  targetUrl: z.string(),
  analyzedAt: z.string(),
  totalEntriesAnalyzed: z.number(),
  exfiltrationDestinations: z.array(z.string()),
  covertWebSocketStreams: z.number(),
  dnsTunnelingIndicators: z.array(z.string()),
  suspiciousPayloadsCount: z.number(),
  chainOfCustodySha256: z.string(),
  forensicIntegrityVerified: z.boolean(),
  forensicFindings: z.array(z.object({
    entryId: z.string(),
    url: z.string(),
    method: z.string(),
    threatCategory: z.string(),
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
    evidenceSnippet: z.string()
  })),
  legalAdmissibilityScore: z.number().min(0).max(100)
});
export type HARForensicArtifact = z.infer<typeof HARForensicArtifactSchema>;

// ============================================================================
// Milestone 20: CTI TAXII Ingestion, BGP Route Integrity & FIDO2 Guard
// ============================================================================

// 1. Decentralized CTI TAXII 2.1 Threat Exchange
export const TAXIIFeedConfigSchema = z.object({
  id: z.string(),
  name: z.string().min(2),
  description: z.string().optional().default(''),
  apiRootUrl: z.string().url(),
  collectionId: z.string(),
  authType: z.enum(['NONE', 'BASIC', 'API_KEY', 'BEARER']).default('NONE'),
  apiKey: z.string().optional(),
  tlpMarking: z.enum(['TLP:WHITE', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']).default('TLP:GREEN'),
  syncIntervalMinutes: z.number().int().min(5).max(1440).default(60),
  isActive: z.boolean().default(true),
  autoBlockIndicators: z.boolean().default(true),
  lastSyncedAt: z.string().optional(),
  totalIndicatorsIngested: z.number().default(0)
});
export type TAXIIFeedConfig = z.infer<typeof TAXIIFeedConfigSchema>;

export const CTIIndicatorSchema = z.object({
  id: z.string(),
  feedId: z.string(),
  indicatorType: z.enum(['URL', 'DOMAIN', 'IPV4', 'IPV6', 'FILE_HASH', 'ATTACK_PATTERN']),
  indicatorValue: z.string(),
  threatType: z.string().default('phishing'),
  confidence: z.number().min(0).max(100),
  tlp: z.enum(['TLP:WHITE', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']),
  stixId: z.string(),
  sourceFeedName: z.string(),
  description: z.string().optional().default(''),
  validFrom: z.string(),
  validUntil: z.string().optional(),
  killChainPhases: z.array(z.string()).default([]),
  tags: z.array(z.string()).default([])
});
export type CTIIndicator = z.infer<typeof CTIIndicatorSchema>;

export const TAXIISyncResultSchema = z.object({
  syncId: z.string(),
  feedId: z.string(),
  feedName: z.string(),
  syncedAt: z.string(),
  indicatorsIngested: z.number(),
  duplicatesSkipped: z.number(),
  highConfidenceThreats: z.number(),
  status: z.enum(['SUCCESS', 'PARTIAL', 'FAILED']),
  errorDetails: z.string().optional(),
  sampleIndicators: z.array(CTIIndicatorSchema).default([])
});
export type TAXIISyncResult = z.infer<typeof TAXIISyncResultSchema>;

export const CTIExchangeStatsSchema = z.object({
  totalFeeds: z.number(),
  activeFeeds: z.number(),
  totalIndicators: z.number(),
  lastSyncTimestamp: z.string().optional(),
  indicatorsByType: z.record(z.string(), z.number()),
  indicatorsByTlp: z.record(z.string(), z.number())
});
export type CTIExchangeStats = z.infer<typeof CTIExchangeStatsSchema>;

// 2. Infrastructure Integrity Radar: BGP Route Hijacking & DNS Cache Poisoning
export const BGPProbeRequestSchema = z.object({
  target: z.string().min(2),
  expectedAsn: z.number().optional(),
  expectedPrefix: z.string().optional(),
  checkDnssec: z.boolean().optional(),
  resolvers: z.array(z.string()).optional()
});
export type BGPProbeRequest = z.infer<typeof BGPProbeRequestSchema>;

export const MultiResolverRecordSchema = z.object({
  resolver: z.string(),
  resolverName: z.string(),
  resolvedIps: z.array(z.string()),
  ttlSeconds: z.number(),
  latencyMs: z.number(),
  dnssecStatus: z.enum(['SECURE', 'INSECURE', 'BOGUS', 'INDETERMINATE']),
  divergentFromConsensus: z.boolean()
});
export type MultiResolverRecord = z.infer<typeof MultiResolverRecordSchema>;

export const BGPIntegrityAssessmentSchema = z.object({
  assessmentId: z.string(),
  target: z.string(),
  resolvedIp: z.string(),
  originAsn: z.number(),
  asOrgName: z.string(),
  asCountry: z.string(),
  announcedPrefix: z.string(),
  rpkiStatus: z.enum(['VALID', 'INVALID', 'NOT_FOUND']),
  isHijackSuspicious: z.boolean(),
  asPathHops: z.array(z.number()),
  asPathAnomalyDetected: z.boolean(),
  dnssecStatus: z.enum(['SECURE', 'INSECURE', 'BOGUS', 'INDETERMINATE']),
  resolverResponses: z.array(MultiResolverRecordSchema),
  dnsPoisoningDetected: z.boolean(),
  routeResolutionIntegrityScore: z.number().min(0).max(100),
  alertSeverity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN']),
  forensicSummary: z.string(),
  evaluatedAt: z.string()
});
export type BGPIntegrityAssessment = z.infer<typeof BGPIntegrityAssessmentSchema>;

// 3. FIDO2 / WebAuthn Phishing-Resistant MFA Guard & Origin Binding Simulator
export const FIDO2ProbeRequestSchema = z.object({
  targetUrl: z.string().min(3),
  claimedBrand: z.string().optional(),
  authProtocol: z.enum([
    'WEBAUTHN_FIDO2',
    'SMS_OTP',
    'EMAIL_OTP',
    'PUSH_NOTIFICATION',
    'TOTP_APP',
    'PASSWORD_ONLY'
  ]).optional(),
  challengeOrigin: z.string().optional(),
  relyingPartyId: z.string().optional()
});
export type FIDO2ProbeRequest = z.infer<typeof FIDO2ProbeRequestSchema>;

export const FIDO2AssessmentResultSchema = z.object({
  evaluationId: z.string(),
  targetUrl: z.string(),
  claimedBrand: z.string(),
  relyingPartyId: z.string(),
  effectiveOrigin: z.string(),
  originBindingMismatch: z.boolean(),
  passkeyImmunityConfirmed: z.boolean(),
  mfaStrengthTier: z.enum([
    'PHISHING_RESISTANT_FIDO2',
    'PHISHING_SUSCEPTIBLE_TOTP',
    'VULNERABLE_LEGACY_SMS',
    'UNPROTECTED_PASSWORD'
  ]),
  mitmProxyVulnerabilityScore: z.number().min(0).max(100),
  proxyEvasionDetected: z.boolean(),
  recommendedSecurityActions: z.array(z.string()),
  webauthnPolicyEnforcementSnippet: z.string(),
  evaluatedAt: z.string()
});
export type FIDO2AssessmentResult = z.infer<typeof FIDO2AssessmentResultSchema>;





