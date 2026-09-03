import { z } from 'zod';

// ============================================================================
// Enums & Literals
// ============================================================================

export const ThreatVerdictSchema = z.enum(['SAFE', 'SUSPICIOUS', 'PHISHING']);
export type ThreatVerdict = z.infer<typeof ThreatVerdictSchema>;

export const RiskLevelSchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const EvidenceSeveritySchema = z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type EvidenceSeverity = z.infer<typeof EvidenceSeveritySchema>;

export const UserRoleSchema = z.enum(['USER', 'ANALYST', 'ADMIN']);
export type UserRole = z.infer<typeof UserRoleSchema>;

// ============================================================================
// Evidence Item Schema
// ============================================================================

export const EvidenceItemSchema = z.object({
  featureKey: z.string(),
  featureValue: z.union([z.string(), z.number(), z.boolean()]),
  severity: EvidenceSeveritySchema,
  description: z.string(),
  contribution: z.number().min(0).max(1).optional()
});
export type EvidenceItem = z.infer<typeof EvidenceItemSchema>;

// ============================================================================
// URL Feature Vector Schema (Extracted deterministic features)
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
// ML Prediction Contracts
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
// Analysis API Contracts
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
// Configurable Risk Engine Constants
// ============================================================================

export const RISK_THRESHOLDS = {
  SAFE_MAX: 29.99,
  SUSPICIOUS_MAX: 59.99,
  HIGH_MAX: 79.99
} as const;

export const RISK_LEVEL_MAP = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
} as const;
