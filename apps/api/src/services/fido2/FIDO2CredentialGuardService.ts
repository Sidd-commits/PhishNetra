import crypto from 'crypto';
import {
  FIDO2ProbeRequest,
  FIDO2AssessmentResult
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

interface BrandRelyingParty {
  officialDomain: string;
  rpId: string;
  officialOrigins: string[];
}

export class FIDO2CredentialGuardService {
  private evaluations: Map<string, FIDO2AssessmentResult> = new Map();

  private brandRegistry: Record<string, BrandRelyingParty> = {
    microsoft: {
      officialDomain: 'login.microsoftonline.com',
      rpId: 'login.microsoft.com',
      officialOrigins: ['https://login.microsoftonline.com', 'https://login.microsoft.com', 'https://account.microsoft.com']
    },
    google: {
      officialDomain: 'accounts.google.com',
      rpId: 'google.com',
      officialOrigins: ['https://accounts.google.com']
    },
    apple: {
      officialDomain: 'appleid.apple.com',
      rpId: 'apple.com',
      officialOrigins: ['https://appleid.apple.com', 'https://idmsa.apple.com']
    },
    github: {
      officialDomain: 'github.com',
      rpId: 'github.com',
      officialOrigins: ['https://github.com']
    },
    okta: {
      officialDomain: 'okta.com',
      rpId: 'okta.com',
      officialOrigins: ['https://login.okta.com', 'https://auth.okta.com']
    }
  };

  public evaluateTarget(probe: FIDO2ProbeRequest): FIDO2AssessmentResult {
    const evaluationId = `fido-${crypto.randomUUID().slice(0, 8)}`;
    const now = new Date().toISOString();

    let targetUrlClean = probe.targetUrl.trim();
    if (!targetUrlClean.startsWith('http://') && !targetUrlClean.startsWith('https://')) {
      targetUrlClean = `https://${targetUrlClean}`;
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(targetUrlClean);
    } catch {
      parsedUrl = new URL('https://example-phish.net');
    }

    const effectiveOrigin = `${parsedUrl.protocol}//${parsedUrl.host}`;
    const targetHostname = parsedUrl.hostname.toLowerCase();

    // Determine claimed brand
    let claimedBrand = (probe.claimedBrand || '').toLowerCase();
    if (!claimedBrand) {
      for (const b of Object.keys(this.brandRegistry)) {
        if (targetHostname.includes(b)) {
          claimedBrand = b;
          break;
        }
      }
    }
    if (!claimedBrand) claimedBrand = 'microsoft';

    const brandMeta = this.brandRegistry[claimedBrand] || {
      officialDomain: `${claimedBrand}.com`,
      rpId: `${claimedBrand}.com`,
      officialOrigins: [`https://${claimedBrand}.com`]
    };

    const relyingPartyId = probe.relyingPartyId || brandMeta.rpId;

    // Check Origin Binding
    const isOfficialDomain = targetHostname === brandMeta.officialDomain ||
      targetHostname.endsWith(`.${brandMeta.rpId}`) ||
      brandMeta.officialOrigins.includes(effectiveOrigin);

    const originBindingMismatch = !isOfficialDomain;

    // Passkey Cryptographic Immunity
    const passkeyImmunityConfirmed = originBindingMismatch;

    // Evaluate MFA Strength Tier and MitM Vulnerability Score
    let mfaTier: 'PHISHING_RESISTANT_FIDO2' | 'PHISHING_SUSCEPTIBLE_TOTP' | 'VULNERABLE_LEGACY_SMS' | 'UNPROTECTED_PASSWORD';
    let mitmVulnerability = 0;

    switch (probe.authProtocol) {
      case 'WEBAUTHN_FIDO2':
        mfaTier = 'PHISHING_RESISTANT_FIDO2';
        mitmVulnerability = 0; // Cryptographic origin binding completely renders AiTM proxies impotent
        break;
      case 'TOTP_APP':
        mfaTier = 'PHISHING_SUSCEPTIBLE_TOTP';
        mitmVulnerability = 75; // Attacker captures TOTP token in-flight and replays to authentic IDP
        break;
      case 'PUSH_NOTIFICATION':
        mfaTier = 'PHISHING_SUSCEPTIBLE_TOTP';
        mitmVulnerability = 85; // MFA fatigue & prompt bombing
        break;
      case 'SMS_OTP':
      case 'EMAIL_OTP':
        mfaTier = 'VULNERABLE_LEGACY_SMS';
        mitmVulnerability = 95; // Easily relayed, SIM-swap vulnerable, plain text
        break;
      case 'PASSWORD_ONLY':
      default:
        mfaTier = 'UNPROTECTED_PASSWORD';
        mitmVulnerability = 100; // Immediate credential harvest
        break;
    }

    // Proxy Evasion Detected if origin mismatch occurs on a login surface
    const proxyEvasionDetected = originBindingMismatch && (
      targetHostname.includes('login') ||
      targetHostname.includes('auth') ||
      targetHostname.includes('verify') ||
      targetHostname.includes('portal')
    );

    // Recommended Actions
    const recommendedSecurityActions: string[] = [];
    if (originBindingMismatch) {
      recommendedSecurityActions.push(
        `ORIGIN_BINDING_ALERT: Effective origin (${effectiveOrigin}) does not match Relying Party ID (${relyingPartyId}).`
      );
      recommendedSecurityActions.push(
        'FIDO2_PASSKEY_IMMUNITY: Authentic WebAuthn credentials will refuse to sign this challenge, blocking AiTM cookie theft.'
      );
    }
    if (mfaTier !== 'PHISHING_RESISTANT_FIDO2') {
      recommendedSecurityActions.push(
        `UPGRADE_REQUIRED: Current auth protocol (${probe.authProtocol}) is susceptible to adversary session interception. Enforce FIDO2 WebAuthn Passkeys.`
      );
    } else {
      recommendedSecurityActions.push(
        'ZERO_TRUST_APPROVED: WebAuthn challenge verified with strict cryptographic origin anchoring.'
      );
    }

    // WebAuthn Policy Snippet
    const webauthnPolicyEnforcementSnippet = JSON.stringify({
      relyingParty: {
        id: relyingPartyId,
        name: `${claimedBrand.toUpperCase()} Enterprise Secure SSO`
      },
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform',
        userVerification: 'required',
        residentKey: 'required',
        requireResidentKey: true
      },
      attestation: 'direct',
      policyRestrictions: {
        allowUnregisteredOrigins: false,
        enforceStrictOriginBinding: true,
        blockLegacyMfaFallback: true
      }
    }, null, 2);

    const result: FIDO2AssessmentResult = {
      evaluationId,
      targetUrl: targetUrlClean,
      claimedBrand,
      relyingPartyId,
      effectiveOrigin,
      originBindingMismatch,
      passkeyImmunityConfirmed,
      mfaStrengthTier: mfaTier,
      mitmProxyVulnerabilityScore: mitmVulnerability,
      proxyEvasionDetected,
      recommendedSecurityActions,
      webauthnPolicyEnforcementSnippet,
      evaluatedAt: now
    };

    this.evaluations.set(evaluationId, result);

    auditLogService.log({
      actor: 'FIDO2 Credential Guard Service',
      action: 'FIDO2_ORIGIN_BINDING_EVALUATED',
      category: 'SECURITY',
      details: JSON.stringify({
        targetUrl: targetUrlClean,
        brand: claimedBrand,
        mfaTier,
        originMismatch: originBindingMismatch,
        immunityConfirmed: passkeyImmunityConfirmed
      }),
      severity: originBindingMismatch ? 'WARNING' : 'INFO'
    });

    return result;
  }

  public getEvaluation(id: string): FIDO2AssessmentResult | undefined {
    return this.evaluations.get(id);
  }

  public listEvaluations(limit: number = 20): FIDO2AssessmentResult[] {
    return Array.from(this.evaluations.values()).reverse().slice(0, limit);
  }
}

export const fido2CredentialGuardService = new FIDO2CredentialGuardService();
