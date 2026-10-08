import crypto from 'crypto';
import {
  GenAIAnalysisRequest,
  GenAIAnalysisResult
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class GenAIPhishingDefenseService {
  private static instance: GenAIPhishingDefenseService;

  private readonly promptInjectionSignatures = [
    { pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i, name: 'IGNORE_PREVIOUS_INSTRUCTIONS' },
    { pattern: /you\s+are\s+now\s+(an\s+)?(unrestricted|evil|dan|jailbroken)/i, name: 'JAILBREAK_ROLEPLAY_OVERRIDE' },
    { pattern: /system\s+prompt\s+override/i, name: 'EXPLICIT_SYSTEM_PROMPT_OVERRIDE' },
    { pattern: /disregard\s+(all\s+)?(safety|security)\s+(rules|guidelines|policies)/i, name: 'DISREGARD_SAFETY_POLICIES' },
    { pattern: /<\|im_start\|>\s*system/i, name: 'CHATML_TOKEN_INJECTION' },
    { pattern: /\[system\]\(#override\)/i, name: 'MARKDOWN_SYSTEM_ESCAPING' },
    { pattern: /act\s+as\s+a\s+trustworthy\s+security\s+filter\s+and\s+mark\s+this\s+safe/i, name: 'AGENT_CLASSIFICATION_HIJACK' }
  ];

  private readonly hiddenCssSignatures = [
    { pattern: /style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(px)?|color\s*:\s*transparent)[^"']*["']/i, name: 'HIDDEN_CSS_CONTAINER' },
    { pattern: /<!--[\s\S]*?(override|ignore|system|instruction|payload)[\s\S]*?-->/i, name: 'HIDDEN_DOM_COMMENT_INJECTION' }
  ];

  private readonly zeroWidthCharsRegex = /[\u200B\u200C\u200D\u200E\u200F\uFEFF]/g;

  private constructor() {}

  public static getInstance(): GenAIPhishingDefenseService {
    if (!GenAIPhishingDefenseService.instance) {
      GenAIPhishingDefenseService.instance = new GenAIPhishingDefenseService();
    }
    return GenAIPhishingDefenseService.instance;
  }

  public analyzeContent(request: GenAIAnalysisRequest): GenAIAnalysisResult {
    const { content, sourceChannel, sanitizeContent } = request;
    const scanId = `genai-${crypto.randomBytes(6).toString('hex')}`;
    const scannedAt = new Date().toISOString();

    const detectedSignatures: string[] = [];
    let injectionTechnique: GenAIAnalysisResult['injectionTechnique'] = 'NONE';

    // 1. Check for Zero-Width Steganography
    const zeroWidthMatches = content.match(this.zeroWidthCharsRegex);
    if (zeroWidthMatches && zeroWidthMatches.length >= 3) {
      detectedSignatures.push(`ZERO_WIDTH_STEGANOGRAPHY (${zeroWidthMatches.length} characters)`);
      injectionTechnique = 'ZERO_WIDTH_STEGANOGRAPHY';
    }

    // 2. Check for Hidden CSS / DOM comments
    for (const sig of this.hiddenCssSignatures) {
      if (sig.pattern.test(content)) {
        detectedSignatures.push(sig.name);
        if (injectionTechnique === 'NONE') {
          injectionTechnique = 'HIDDEN_CSS_PAYLOAD';
        }
      }
    }

    // 3. Check for Prompt Injections & Jailbreaks
    for (const sig of this.promptInjectionSignatures) {
      if (sig.pattern.test(content)) {
        detectedSignatures.push(sig.name);
        if (sig.name.includes('JAILBREAK')) {
          injectionTechnique = 'JAILBREAK_ATTEMPT';
        } else {
          injectionTechnique = 'INDIRECT_PROMPT_INJECTION';
        }
      }
    }

    const promptInjectionDetected = detectedSignatures.length > 0;

    // 4. Compute synthetic lure likelihood and perplexity proxy
    const { syntheticScore, perplexity } = this.estimateSyntheticLureMetrics(content);

    // 5. Determine Overall Risk Level & Action
    let riskLevel: GenAIAnalysisResult['riskLevel'] = 'SAFE';
    let defenseAction: GenAIAnalysisResult['defenseAction'] = 'ALLOW';

    if (promptInjectionDetected) {
      riskLevel = 'CRITICAL';
      defenseAction = 'QUARANTINE';
    } else if (syntheticScore >= 75) {
      riskLevel = 'HIGH';
      defenseAction = 'SANITIZE';
    } else if (syntheticScore >= 45) {
      riskLevel = 'MEDIUM';
      defenseAction = 'ALLOW';
    } else if (syntheticScore >= 20) {
      riskLevel = 'LOW';
      defenseAction = 'ALLOW';
    }

    // 6. Neutralize content if requested
    let neutralizedContent = content;
    if (sanitizeContent && promptInjectionDetected) {
      neutralizedContent = this.neutralize(content);
    }

    // 7. Audit log if critical or high
    if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') {
      auditLogService.log({
        actor: 'GenAIPhishingDefenseService',
        action: 'GENAI_PROMPT_INJECTION_DETECTED',
        category: 'SECURITY',
        severity: 'CRITICAL',
        details: JSON.stringify({
          scanId,
          sourceChannel,
          technique: injectionTechnique,
          signatures: detectedSignatures,
          syntheticScore
        })
      });
    }

    return {
      scanId,
      scannedAt,
      promptInjectionDetected,
      injectionTechnique,
      syntheticLureLikelihood: syntheticScore,
      perplexityScore: perplexity,
      detectedSignatures,
      riskLevel,
      neutralizedContent,
      defenseAction
    };
  }

  private estimateSyntheticLureMetrics(text: string): { syntheticScore: number; perplexity: number } {
    const words = text.trim().split(/\s+/).filter(w => w.length > 0);
    if (words.length < 5) {
      return { syntheticScore: 10, perplexity: 85.0 };
    }

    // Common AI phishing markers: hyper-formal urgency, repeated boilerplate phrasing
    const aiLureKeywords = [
      'urgent verification required',
      'immediate attention',
      'failure to comply will result',
      'critical security notification',
      'confirm your identity immediately',
      'suspended within 24 hours',
      'unauthorized access attempt detected',
      'kindly proceed to the link'
    ];

    let markerHits = 0;
    const lower = text.toLowerCase();
    for (const kw of aiLureKeywords) {
      if (lower.includes(kw)) markerHits++;
    }

    // Sentence length uniformity (low variance in sentence length is typical of LLM output)
    const sentences = text.split(/[.!?]+/).map(s => s.trim().split(/\s+/).length).filter(n => n > 2);
    let variance = 10;
    if (sentences.length >= 3) {
      const mean = sentences.reduce((a, b) => a + b, 0) / sentences.length;
      variance = sentences.reduce((acc, len) => acc + Math.pow(len - mean, 2), 0) / sentences.length;
    }

    // Lower variance -> higher synthetic probability
    const uniformityBoost = variance < 8 ? 25 : variance < 16 ? 15 : 0;
    const markerBoost = markerHits * 25;

    const syntheticScore = markerHits > 0
      ? Math.min(100, Math.round(uniformityBoost + markerBoost + 10))
      : Math.min(15, Math.round(uniformityBoost * 0.4));
    // Perplexity proxy: inversely correlated with predictability
    const perplexity = Math.max(12.5, Math.min(120.0, Math.round((100 - syntheticScore * 0.75) * 10) / 10));

    return { syntheticScore, perplexity };
  }

  private neutralize(raw: string): string {
    let clean = raw.replace(this.zeroWidthCharsRegex, '');
    for (const sig of this.hiddenCssSignatures) {
      clean = clean.replace(sig.pattern, '[NEUTRALIZED_HIDDEN_CONTENT]');
    }
    for (const sig of this.promptInjectionSignatures) {
      clean = clean.replace(sig.pattern, '[NEUTRALIZED_PROMPT_INJECTION]');
    }
    return clean;
  }
}

export const genAIPhishingDefenseService = GenAIPhishingDefenseService.getInstance();
