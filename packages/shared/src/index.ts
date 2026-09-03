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

export const DetectionLayerSchema = z.enum(['URL', 'DOMAIN', 'DNS', 'TLS', 'REPUTATION', 'ML']);
export type DetectionLayer = z.infer<typeof DetectionLayerSchema>;

export const LayerStatusSchema = z.enum(['SUCCESS', 'PARTIAL', 'NOT_CONFIGURED', 'FAILED', 'SKIPPED']);
export type LayerStatus = z.infer<typeof LayerStatusSchema>;

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
// Multi-Layer Intelligence Result Schemas (Milestone 2)
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

// Combined Multi-Layer Result
export const MultiLayerDataSchema = z.object({
  url: URLIntelligenceSchema,
  domain: DomainIntelligenceSchema,
  dns: DNSIntelligenceSchema,
  tls: TLSIntelligenceSchema,
  reputation: ReputationIntelligenceSchema,
  ml: MLIntelligenceSchema
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

// ============================================================================
// Analysis API Response Contracts (Backward Compatible + Enhanced)
// ============================================================================

export const AnalysisRequestSchema = z.object({
  url: z.string().url('Invalid URL format. Please provide a complete URL starting with http:// or https://')
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
  evidence: z.array(EvidenceItemSchema),
  features: URLFeatureVectorSchema.optional(),
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
  URL: 0.20,
  DOMAIN: 0.15,
  DNS: 0.10,
  TLS: 0.10,
  REPUTATION: 0.25,
  ML: 0.20
} as const;

export const RISK_THRESHOLDS = {
  SAFE_MAX: 29.99,
  SUSPICIOUS_MAX: 59.99,
  HIGH_MAX: 79.99
} as const;
