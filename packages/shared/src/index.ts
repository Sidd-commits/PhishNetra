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
  src: z.string(),
  srcResolved: z.string().optional(),
  isCrossOrigin: z.boolean(),
  isHidden: z.boolean(),
  width: z.string().optional(),
  height: z.string().optional()
});
export type IFrameFinding = z.infer<typeof IFrameFindingSchema>;

export const ScriptFindingSchema = z.object({
  src: z.string().optional(),
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

