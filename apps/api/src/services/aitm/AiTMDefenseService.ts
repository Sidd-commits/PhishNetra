import {
  AiTMSessionScanRequest,
  AiTMSessionScanResult,
  AiTMProxyIndicator,
  AiTMThreatType
} from '@phishnetra/shared';
import crypto from 'crypto';

export class AiTMDefenseService {
  /**
   * Evaluates an incoming session or URL for Adversary-in-the-Middle (AiTM) reverse proxy signatures
   */
  public static scanSession(req: AiTMSessionScanRequest): AiTMSessionScanResult {
    const indicators: AiTMProxyIndicator[] = [];
    const targetUrl = req.targetUrl.trim();
    const headers = req.headers || {};
    const cookies = req.cookiesPresent || [];
    const claimedHost = req.claimedHost?.toLowerCase().trim();

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(targetUrl);
    } catch {
      parsedUrl = new URL(`https://${targetUrl}`);
    }

    const currentHost = parsedUrl.hostname.toLowerCase();

    // 1. Domain Binding Mismatch / Multi-Domain Lookalike Proxy
    const enterpriseDomains = [
      'login.microsoftonline.com',
      'accounts.google.com',
      'login.live.com',
      'auth.okta.com',
      'idp.pingidentity.com',
      'github.com'
    ];

    for (const ent of enterpriseDomains) {
      if (
        currentHost !== ent &&
        (currentHost.includes(ent.replace('.', '-')) ||
          currentHost.includes(ent) ||
          (claimedHost && claimedHost === ent))
      ) {
        indicators.push({
          type: 'DOMAIN_BINDING_MISMATCH',
          severity: 'CRITICAL',
          description: `Target host "${currentHost}" impersonates enterprise identity provider "${ent}" via AiTM proxy domain tunneling.`,
          detectedPattern: `host=${currentHost}; authentic=${ent}`
        });
      }
    }

    // 2. Reverse Proxy Engine Header Signatures (Evilginx, Modlishka, Muraena)
    const headerKeys = Object.keys(headers).map(k => k.toLowerCase());
    const headerValues = Object.values(headers).join(' ').toLowerCase();

    if (
      headerKeys.some(k => k.includes('evilginx') || k.includes('modlishka') || k.includes('muraena')) ||
      headerValues.includes('evilginx')
    ) {
      indicators.push({
        type: 'AITM_PROXY_TOOL_SIGNATURE',
        severity: 'CRITICAL',
        description: 'Direct heuristic signature match of known AiTM reverse proxy engine (Evilginx/Modlishka).',
        detectedPattern: 'Tool fingerprint in HTTP headers/proxy transport'
      });
    }

    // 3. Upstream Discrepancies & Header Injection
    if (
      headers['x-forwarded-host'] &&
      headers['x-forwarded-host'].toLowerCase() !== currentHost
    ) {
      indicators.push({
        type: 'HEADER_INJECTION_ANOMALY',
        severity: 'HIGH',
        description: 'X-Forwarded-Host header diverts from target authority, indicating an unauthenticated reverse-proxy relay.',
        detectedPattern: `X-Forwarded-Host: ${headers['x-forwarded-host']} != ${currentHost}`
      });
    }

    // 4. Session Cookie Interception & MFA Theft Risk
    const highValueSessionCookies = [
      'ESTSAUTH',
      'ESTSAUTHPERSISTENT',
      'auth_jwt',
      'session_token',
      'li_at',
      'connect.sid',
      'SSID',
      'remember_token'
    ];

    const interceptedCookies = cookies.filter(c =>
      highValueSessionCookies.some(hvc => c.toUpperCase().includes(hvc.toUpperCase()))
    );

    if (interceptedCookies.length > 0 && indicators.length > 0) {
      indicators.push({
        type: 'COOKIE_SESSION_INTERCEPT',
        severity: 'CRITICAL',
        description: `High-value enterprise authentication cookies (${interceptedCookies.join(', ')}) transmitted through suspect reverse proxy.`,
        detectedPattern: `Vulnerable tokens: ${interceptedCookies.join(', ')}`
      });
    }

    // Determine Overall Threat Status
    const isAiTMProxy = indicators.some(i => i.severity === 'CRITICAL' || i.severity === 'HIGH');
    let threatType: AiTMThreatType | null = null;
    let riskScore = 15;
    let recommendedAction: 'BLOCK_AND_INVALIDATE' | 'ENFORCE_FIDO2_STEPUP' | 'FLAG_SUSPICIOUS' | 'ALLOW' = 'ALLOW';

    if (isAiTMProxy) {
      riskScore = 96;
      threatType = indicators.some(i => i.type === 'COOKIE_SESSION_INTERCEPT')
        ? 'COOKIE_SESSION_INTERCEPT'
        : indicators.some(i => i.type === 'AITM_PROXY_TOOL_SIGNATURE')
        ? 'EVILGINX_REVERSE_PROXY'
        : 'DOMAIN_BINDING_MISMATCH';

      recommendedAction = interceptedCookies.length > 0 ? 'BLOCK_AND_INVALIDATE' : 'ENFORCE_FIDO2_STEPUP';
    } else if (indicators.length > 0) {
      riskScore = 55;
      threatType = 'HEADER_INJECTION_ANOMALY';
      recommendedAction = 'FLAG_SUSPICIOUS';
    }

    // Generate Autonomous Mitigation Artifact
    const mitigationArtifact = isAiTMProxy
      ? `# PhishNetra AiTM Defense Directive
# Target: ${currentHost}
# Threat: ${threatType || 'AITM_REVERSE_PROXY'}

# 1. Invalidate Session & Force WebAuthn/FIDO2 Step-up
REVOKE_SESSION_ID: ${crypto.randomBytes(8).toString('hex')}
ACTION: ENFORCE_PASSKEY_FIDO2_CREDENTIAL_BOUND_AUTHENTICATION

# 2. Snort / Suricata NIDS Rule
alert tcp any any -> any any (msg:"PhishNetra AiTM Proxy Traffic Intercept - ${currentHost}"; content:"${currentHost}"; http_header; classtype:trojan-activity; sid:9000101; rev:1;)

# 3. BIND9 DNS RPZ Quarantine
${currentHost} CNAME .
*.${currentHost} CNAME .`
      : '# No active AiTM proxy detected for target.';

    return {
      id: `aitm-${crypto.randomBytes(6).toString('hex')}`,
      targetUrl,
      isAiTMProxy,
      threatType,
      riskScore,
      indicators,
      recommendedAction,
      mitigationArtifact,
      evaluatedAt: new Date().toISOString()
    };
  }
}
