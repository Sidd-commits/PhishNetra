import crypto from 'crypto';
import {
  CreateRBISessionRequest,
  RBIBrowserEvent,
  RBISecurityPolicy,
  RBISession
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class RemoteBrowserIsolationService {
  private static instance: RemoteBrowserIsolationService;

  private sessions: Map<string, RBISession> = new Map();

  constructor() {
    this.seedDefaultSessions();
  }

  public static getInstance(): RemoteBrowserIsolationService {
    if (!RemoteBrowserIsolationService.instance) {
      RemoteBrowserIsolationService.instance = new RemoteBrowserIsolationService();
    }
    return RemoteBrowserIsolationService.instance;
  }

  private defaultPolicy(): RBISecurityPolicy {
    return {
      blockWebSockets: true,
      blockWebRTC: true,
      blockClipboardWrite: true,
      blockFormSubmit: true,
      canvasRandomization: true,
      stripMaliciousScripts: true,
      enforceZeroTrustCSP: true
    };
  }

  private deWeaponizeHtml(targetUrl: string, domain: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data: https:; style-src 'unsafe-inline'; font-src data:;">
  <title>RBI Isolated Sandbox: ${domain}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }
    .sandbox-banner { background: rgba(244, 63, 94, 0.15); border: 1px solid rgba(244, 63, 94, 0.4); border-radius: 12px; padding: 12px 16px; margin-bottom: 20px; color: #fda4af; font-size: 13px; font-weight: 600; display: flex; align-items: center; justify-content: space-between; }
    .phish-form { max-width: 420px; margin: 40px auto; background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 28px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
    .form-title { font-size: 18px; font-weight: bold; margin-bottom: 8px; color: #fff; text-align: center; }
    .form-desc { font-size: 12px; color: #94a3b8; text-align: center; margin-bottom: 24px; }
    .input-group { margin-bottom: 16px; }
    .input-group label { display: block; font-size: 11px; font-weight: 600; text-transform: uppercase; color: #cbd5e1; margin-bottom: 6px; }
    .input-group input { width: 100%; box-sizing: border-box; background: #0f172a; border: 1px solid #475569; border-radius: 8px; padding: 10px 14px; font-size: 13px; color: #fff; }
    .input-group input:disabled { background: #1e293b; color: #64748b; cursor: not-allowed; }
    .de-weaponized-btn { width: 100%; padding: 12px; background: #ef4444; border: none; border-radius: 8px; font-size: 13px; font-weight: bold; color: #fff; cursor: not-allowed; opacity: 0.8; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 10px; font-family: monospace; font-weight: 700; background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
  </style>
</head>
<body>
  <div class="sandbox-banner">
    <div>🛡️ <strong>PHISHNETRA ZERO-TRUST RBI SANDBOX</strong> &bull; JavaScript & Sockets De-Weaponized</div>
    <span class="badge">AIR-GAPPED STREAM</span>
  </div>
  <div class="phish-form">
    <div class="form-title">Account Security Verification</div>
    <div class="form-desc">Simulated Capture of Target: <code>${domain}</code></div>
    <div class="input-group">
      <label>Email Address or Username</label>
      <input type="text" value="user@corporate.target" disabled />
    </div>
    <div class="input-group">
      <label>Password</label>
      <input type="password" value="••••••••••••" disabled />
    </div>
    <button class="de-weaponized-btn" disabled>Form Submissions Intercepted by Sandbox</button>
  </div>
</body>
</html>`;
  }

  private seedDefaultSessions(): void {
    const defaultSession: RBISession = {
      id: 'rbi-001',
      targetUrl: 'https://auth-sec-verify-microsoft.account-portal.xyz/login',
      domain: 'auth-sec-verify-microsoft.account-portal.xyz',
      status: 'RUNNING',
      securityPolicy: this.defaultPolicy(),
      containerId: 'cnt-rbi-98a2f1c8',
      sandboxResolution: '1280x800',
      liveEvents: [
        {
          id: 'ev-001',
          timestamp: new Date(Date.now() - 3600 * 1000).toISOString(),
          eventType: 'NAVIGATE',
          severity: 'INFO',
          details: 'Ephemeral isolated container allocated with strict Zero-Trust Content-Security-Policy.'
        },
        {
          id: 'ev-002',
          timestamp: new Date(Date.now() - 3500 * 1000).toISOString(),
          eventType: 'EVAL_BLOCKED',
          severity: 'HIGH',
          details: 'Obfuscated JavaScript eval(String.fromCharCode(...)) neutralized by RBI script proxy.'
        },
        {
          id: 'ev-003',
          timestamp: new Date(Date.now() - 3400 * 1000).toISOString(),
          eventType: 'KEYLOGGER_INTERCEPTED',
          severity: 'CRITICAL',
          details: 'Window keydown hook attempting keystroke exfiltration to telegram drop-box blocked.'
        },
        {
          id: 'ev-004',
          timestamp: new Date(Date.now() - 3300 * 1000).toISOString(),
          eventType: 'CANVAS_PROBE_CLOAKED',
          severity: 'MEDIUM',
          details: 'Canvas 2D fingerprinting probe returned randomized synthetic pixel noise.'
        },
        {
          id: 'ev-005',
          timestamp: new Date(Date.now() - 3200 * 1000).toISOString(),
          eventType: 'FORM_SUBMIT_BLOCKED',
          severity: 'CRITICAL',
          details: 'Cross-origin POST request to unauthenticated IP destination intercepted.'
        }
      ],
      deWeaponizedHtml: this.deWeaponizeHtml('https://auth-sec-verify-microsoft.account-portal.xyz/login', 'auth-sec-verify-microsoft.account-portal.xyz'),
      activeTabTitle: 'Microsoft Security Verification (Isolated)',
      startedAt: new Date(Date.now() - 3600 * 1000).toISOString(),
      terminatedAt: null
    };

    this.sessions.set(defaultSession.id, defaultSession);
  }

  public listSessions(): RBISession[] {
    return Array.from(this.sessions.values()).sort(
      (a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
    );
  }

  public getSession(id: string): RBISession | null {
    return this.sessions.get(id) || null;
  }

  public createSession(req: CreateRBISessionRequest, actor: { id: string; name: string }): RBISession {
    const id = `rbi-${crypto.randomBytes(4).toString('hex')}`;
    const domain = req.targetUrl.startsWith('http')
      ? new URL(req.targetUrl).hostname
      : req.targetUrl;
    const now = new Date().toISOString();

    const policy: RBISecurityPolicy = {
      ...this.defaultPolicy(),
      ...(req.securityPolicy || {})
    };

    const session: RBISession = {
      id,
      targetUrl: req.targetUrl,
      domain,
      status: 'RUNNING',
      securityPolicy: policy,
      containerId: `cnt-rbi-${crypto.randomBytes(4).toString('hex')}`,
      sandboxResolution: '1280x800',
      liveEvents: [
        {
          id: `ev-${crypto.randomBytes(3).toString('hex')}`,
          timestamp: now,
          eventType: 'NAVIGATE',
          severity: 'INFO',
          details: `Zero-Trust isolated browser container spun up for target: ${domain}`
        },
        {
          id: `ev-${crypto.randomBytes(3).toString('hex')}`,
          timestamp: new Date(Date.now() + 500).toISOString(),
          eventType: 'EVAL_BLOCKED',
          severity: 'HIGH',
          details: 'Dynamic script execution hooks neutralized with Zero-Trust CSP barrier.'
        }
      ],
      deWeaponizedHtml: this.deWeaponizeHtml(req.targetUrl, domain),
      activeTabTitle: `${domain} (Air-Gapped Sandbox)`,
      startedAt: now,
      terminatedAt: null
    };

    this.sessions.set(id, session);

    auditLogService.log({
      actor: actor.name,
      action: 'CREATE_RBI_SESSION',
      category: 'ANALYSIS',
      target: id,
      details: `Initialized Remote Browser Isolation sandbox session for ${domain}`,
      severity: 'INFO'
    });

    return session;
  }

  public terminateSession(id: string, actor: { id: string; name: string }): RBISession | null {
    const session = this.sessions.get(id);
    if (!session) return null;

    session.status = 'TERMINATED';
    session.terminatedAt = new Date().toISOString();
    this.sessions.set(id, session);

    auditLogService.log({
      actor: actor.name,
      action: 'TERMINATE_RBI_SESSION',
      category: 'ANALYSIS',
      target: id,
      details: `Terminated Remote Browser Isolation session ${id}`,
      severity: 'INFO'
    });

    return session;
  }
}

export const remoteBrowserIsolationService = RemoteBrowserIsolationService.getInstance();
