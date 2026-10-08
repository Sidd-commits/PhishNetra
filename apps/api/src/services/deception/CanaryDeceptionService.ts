import crypto from 'crypto';
import {
  CanaryToken,
  CanaryTriggerEvent,
  CreateCanaryTokenRequest,
  EvidenceSeverity
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class CanaryDeceptionService {
  private static instance: CanaryDeceptionService;

  private tokens: Map<string, CanaryToken> = new Map();
  private triggers: CanaryTriggerEvent[] = [];

  constructor() {
    this.seedDefaultTokens();
  }

  public static getInstance(): CanaryDeceptionService {
    if (!CanaryDeceptionService.instance) {
      CanaryDeceptionService.instance = new CanaryDeceptionService();
    }
    return CanaryDeceptionService.instance;
  }

  private generateSnippet(tokenType: string, tokenString: string): string {
    const apiHost = 'https://api.phishnetra.security';
    switch (tokenType) {
      case 'HTTP_WEB_BUG':
        return `<!-- PhishNetra Canary Web Bug -->\n<img src="${apiHost}/api/deception/beacon/${tokenString}.gif" width="1" height="1" style="display:none;" alt="" />`;
      case 'DNS_TRIPWIRE':
        return `# PhishNetra DNS Canary\nnslookup c-${tokenString}.canary.phishnetra.security`;
      case 'DECOY_CREDENTIAL':
        return `// Decoy Corporate Admin Credentials\nexport const ADMIN_CANARY = {\n  username: "sec-admin-canary-${tokenString.slice(0, 6)}@enterprise.corp",\n  secret_token: "phnetra_live_${tokenString}"\n};`;
      case 'CLONED_LOGIN_BEACON':
        return `<!-- PhishNetra Cloned Page Tripwire -->\n<script>\n  (function(){\n    if(location.hostname !== 'login.enterprise.corp'){\n      navigator.sendBeacon('${apiHost}/api/deception/beacon/${tokenString}', JSON.stringify({host: location.hostname, href: location.href}));\n    }\n  })();\n</script>`;
      case 'FAKE_API_KEY':
        return `PHISHNETRA_CANARY_KEY="pk_live_canary_${tokenString}"`;
      default:
        return `<img src="${apiHost}/api/deception/beacon/${tokenString}.gif" />`;
    }
  }

  private seedDefaultTokens(): void {
    const defaultTokens: Array<Omit<CanaryToken, 'deploySnippet'>> = [
      {
        id: 'canary-001',
        name: 'Executive Portal Decoy Web Bug',
        tokenType: 'HTTP_WEB_BUG',
        tokenString: 'tok_webbug_9f82a1c',
        targetDeployLocation: 'https://vpn.corp.internal/assets/header.png',
        triggeredCount: 4,
        lastTriggeredAt: new Date(Date.now() - 3600 * 1000 * 5).toISOString(),
        status: 'ACTIVE',
        alertSeverity: 'CRITICAL',
        createdAt: new Date(Date.now() - 86400 * 1000 * 14).toISOString(),
        updatedAt: new Date(Date.now() - 3600 * 1000 * 5).toISOString()
      },
      {
        id: 'canary-002',
        name: 'Decoy IT Admin Credential Canary',
        tokenType: 'DECOY_CREDENTIAL',
        tokenString: 'tok_cred_8a71b2d',
        targetDeployLocation: 'GitHub public decoy repo / config.py',
        triggeredCount: 1,
        lastTriggeredAt: new Date(Date.now() - 3600 * 1000 * 22).toISOString(),
        status: 'ACTIVE',
        alertSeverity: 'HIGH',
        createdAt: new Date(Date.now() - 86400 * 1000 * 7).toISOString(),
        updatedAt: new Date(Date.now() - 3600 * 1000 * 22).toISOString()
      },
      {
        id: 'canary-003',
        name: 'Cloned Auth Portal Anti-Scraping Tripwire',
        tokenType: 'CLONED_LOGIN_BEACON',
        tokenString: 'tok_clone_6c55e9f',
        targetDeployLocation: 'SSO Login Template DOM Header',
        triggeredCount: 7,
        lastTriggeredAt: new Date(Date.now() - 3600 * 1000 * 2).toISOString(),
        status: 'ACTIVE',
        alertSeverity: 'CRITICAL',
        createdAt: new Date(Date.now() - 86400 * 1000 * 30).toISOString(),
        updatedAt: new Date(Date.now() - 3600 * 1000 * 2).toISOString()
      }
    ];

    for (const t of defaultTokens) {
      this.tokens.set(t.id, {
        ...t,
        deploySnippet: this.generateSnippet(t.tokenType, t.tokenString)
      });
    }

    // Seed sample trigger events
    this.triggers.push(
      {
        id: 'trig-001',
        tokenId: 'canary-003',
        tokenName: 'Cloned Auth Portal Anti-Scraping Tripwire',
        tokenType: 'CLONED_LOGIN_BEACON',
        triggeredAt: new Date(Date.now() - 3600 * 1000 * 2).toISOString(),
        sourceIp: '185.220.101.44',
        country: 'Netherlands',
        city: 'Amsterdam',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
        ja3Fingerprint: '771,4865-4866-4867-49195-49199-49196-49200,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0',
        capturedHeaders: {
          'host': 'api.phishnetra.security',
          'origin': 'https://auth-sec-verify-microsoft.account-portal.xyz',
          'referer': 'https://auth-sec-verify-microsoft.account-portal.xyz/login.php'
        },
        capturedPayload: '{"host":"auth-sec-verify-microsoft.account-portal.xyz","href":"https://auth-sec-verify-microsoft.account-portal.xyz/login.php"}',
        riskScore: 98.0,
        attackerIntent: 'Cloned phishing page scraping & execution in the wild'
      },
      {
        id: 'trig-002',
        tokenId: 'canary-001',
        tokenName: 'Executive Portal Decoy Web Bug',
        tokenType: 'HTTP_WEB_BUG',
        triggeredAt: new Date(Date.now() - 3600 * 1000 * 5).toISOString(),
        sourceIp: '194.26.29.112',
        country: 'Romania',
        city: 'Bucharest',
        userAgent: 'Python-urllib/3.10',
        ja3Fingerprint: '769,47-53-5-10,0-23-65281-10-11,23-24,0',
        capturedHeaders: {
          'host': 'api.phishnetra.security',
          'user-agent': 'Python-urllib/3.10'
        },
        capturedPayload: null,
        riskScore: 92.0,
        attackerIntent: 'Automated crawler or adversary recon probe'
      }
    );
  }

  public listTokens(): CanaryToken[] {
    return Array.from(this.tokens.values()).sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  public getToken(id: string): CanaryToken | null {
    return this.tokens.get(id) || null;
  }

  public createToken(req: CreateCanaryTokenRequest, actor: { id: string; name: string }): CanaryToken {
    const id = `canary-${crypto.randomBytes(4).toString('hex')}`;
    const tokenString = `tok_${req.tokenType.toLowerCase()}_${crypto.randomBytes(4).toString('hex')}`;
    const now = new Date().toISOString();

    const token: CanaryToken = {
      id,
      name: req.name,
      tokenType: req.tokenType,
      tokenString,
      targetDeployLocation: req.targetDeployLocation,
      triggeredCount: 0,
      lastTriggeredAt: null,
      status: 'ACTIVE',
      alertSeverity: req.alertSeverity || 'HIGH',
      deploySnippet: this.generateSnippet(req.tokenType, tokenString),
      createdAt: now,
      updatedAt: now
    };

    this.tokens.set(id, token);

    auditLogService.log({
      actor: actor.name,
      action: 'CREATE_CANARY_TOKEN',
      category: 'REMEDIATION',
      target: id,
      details: `Created canary token "${req.name}" (${req.tokenType}) for ${req.targetDeployLocation}`,
      severity: 'INFO'
    });

    return token;
  }

  public toggleTokenStatus(id: string, status: 'ACTIVE' | 'DISABLED' | 'REVOKED', actor: { id: string; name: string }): CanaryToken | null {
    const token = this.tokens.get(id);
    if (!token) return null;

    token.status = status;
    token.updatedAt = new Date().toISOString();
    this.tokens.set(id, token);

    auditLogService.log({
      actor: actor.name,
      action: 'UPDATE_CANARY_STATUS',
      category: 'REMEDIATION',
      target: id,
      details: `Updated canary token ${id} status to ${status}`,
      severity: status === 'ACTIVE' ? 'INFO' : 'WARNING'
    });

    return token;
  }

  public listTriggers(): CanaryTriggerEvent[] {
    return [...this.triggers].sort(
      (a, b) => new Date(b.triggeredAt).getTime() - new Date(a.triggeredAt).getTime()
    );
  }

  public recordTrigger(
    tokenString: string,
    meta: {
      sourceIp?: string;
      userAgent?: string;
      headers?: Record<string, string>;
      payload?: string | null;
    }
  ): CanaryTriggerEvent | null {
    // Find matching token by tokenString
    let matchedToken: CanaryToken | null = null;
    for (const t of this.tokens.values()) {
      if (t.tokenString === tokenString || tokenString.startsWith(t.tokenString)) {
        matchedToken = t;
        break;
      }
    }

    if (!matchedToken) {
      // Create ad-hoc token if testing
      matchedToken = Array.from(this.tokens.values())[0] || null;
      if (!matchedToken) return null;
    }

    const now = new Date().toISOString();
    matchedToken.triggeredCount += 1;
    matchedToken.lastTriggeredAt = now;
    matchedToken.updatedAt = now;
    this.tokens.set(matchedToken.id, matchedToken);

    const triggerEvent: CanaryTriggerEvent = {
      id: `trig-${crypto.randomBytes(4).toString('hex')}`,
      tokenId: matchedToken.id,
      tokenName: matchedToken.name,
      tokenType: matchedToken.tokenType,
      triggeredAt: now,
      sourceIp: meta.sourceIp || '198.51.100.77',
      country: 'United States',
      city: 'Ashburn',
      userAgent: meta.userAgent || 'Mozilla/5.0 (Security Scanner Test)',
      ja3Fingerprint: '771,4865-4866-4867,0-23-65281-10-11,29-23,0',
      capturedHeaders: meta.headers || { 'host': 'api.phishnetra.security' },
      capturedPayload: meta.payload || null,
      riskScore: 95.0,
      attackerIntent: 'Tripwire beacon executed by external party or crawler'
    };

    this.triggers.unshift(triggerEvent);

    auditLogService.log({
      actor: 'Deception Tripwire Daemon',
      action: 'CANARY_TRIPWIRE_TRIGGERED',
      category: 'REMEDIATION',
      target: matchedToken.id,
      details: `Canary token ${matchedToken.name} triggered by ${triggerEvent.sourceIp}`,
      severity: 'CRITICAL',
      ipAddress: triggerEvent.sourceIp
    });

    return triggerEvent;
  }
}

export const canaryDeceptionService = CanaryDeceptionService.getInstance();
