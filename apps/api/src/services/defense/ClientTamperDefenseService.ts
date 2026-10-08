import {
  ClientGuardConfig,
  ClientGuardScriptResult,
  ClientTamperEvent
} from '@phishnetra/shared';
import crypto from 'crypto';
import { auditLogService } from '../audit/AuditLogService';

export class ClientTamperDefenseService {
  private events: ClientTamperEvent[] = [
    {
      eventId: 'tmp-seed-01',
      timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
      targetDomain: 'identity.enterprise-sso.internal',
      tamperType: 'DOM_OVERLAY_INJECTED',
      clientIp: '198.51.100.44',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      payloadDetails: {
        injectedElement: 'DIV#fake-password-prompt',
        targetFormAction: 'https://attacker-c2.live/collect'
      },
      severity: 'CRITICAL'
    },
    {
      eventId: 'tmp-seed-02',
      timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
      targetDomain: 'portal.enterprise-sso.internal',
      tamperType: 'DEVTOOLS_OPENED',
      clientIp: '203.0.113.88',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      payloadDetails: {
        debuggerDeltaMs: 240,
        consoleInspected: true
      },
      severity: 'MEDIUM'
    }
  ];

  public generateGuardScript(config: ClientGuardConfig): ClientGuardScriptResult {
    const configId = `cfg-${crypto.randomUUID()}`;
    const generatedAt = new Date().toISOString();

    const scriptCode = `
/**
 * PhishNetra Client-Side Anti-Tampering & DOM Cloaking Guard
 * Target Domain: ${config.targetDomain}
 * Build Hash: ${configId}
 */
(function(window, document) {
  'use strict';
  const ENDPOINT = '${config.reportingEndpoint}';
  const DOMAIN = '${config.targetDomain}';

  function report(type, details, severity) {
    const payload = JSON.stringify({
      targetDomain: DOMAIN,
      tamperType: type,
      payloadDetails: details,
      severity: severity || 'HIGH',
      timestamp: new Date().toISOString()
    });
    if (navigator.sendBeacon) {
      navigator.sendBeacon(ENDPOINT, payload);
    } else {
      fetch(ENDPOINT, { method: 'POST', body: payload, headers: { 'Content-Type': 'application/json' } }).catch(() => {});
    }
  }

  ${config.enableClickjackingTrap ? `
  // Anti-Clickjacking / Framing Trap
  try {
    if (window.top !== window.self) {
      report('CLICKJACKING_IFRAME_DETECTED', { topLocation: String(window.top.location.href || 'cross-origin') }, 'HIGH');
      window.top.location = window.self.location.href;
    }
  } catch (e) {
    report('CLICKJACKING_IFRAME_DETECTED', { blockedAccess: true }, 'HIGH');
  }
  ` : ''}

  ${config.enableDevToolsTrap ? `
  // DevTools & Debugger Trap
  let lastTime = performance.now();
  setInterval(function() {
    const now = performance.now();
    if (now - lastTime > 150) {
      report('DEVTOOLS_OPENED', { deltaMs: Math.round(now - lastTime) }, 'MEDIUM');
    }
    lastTime = now;
  }, 1000);
  ` : ''}

  ${config.enableMutationTrap ? `
  // DOM Mutation Observer Overlay Trap
  if (window.MutationObserver) {
    const observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        mutation.addedNodes.forEach(function(node) {
          if (node.nodeType === 1) {
            const tag = node.tagName.toLowerCase();
            if (tag === 'input' || tag === 'form' || tag === 'iframe') {
              const action = node.getAttribute('action') || node.getAttribute('src');
              if (action && !action.includes(DOMAIN)) {
                report('DOM_OVERLAY_INJECTED', { tag: tag, action: action }, 'CRITICAL');
                node.remove();
              }
            }
          }
        });
      });
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }
  ` : ''}
})(window, document);
`.trim();

    const scriptIntegrityHash = `sha256-${crypto.createHash('sha256').update(scriptCode).digest('base64')}`;

    auditLogService.log({
      actor: 'SYSTEM',
      action: 'CLIENT_GUARD_SCRIPT_GENERATED',
      details: JSON.stringify({ configId, targetDomain: config.targetDomain, scriptIntegrityHash }),
      category: 'SECURITY',
      severity: 'INFO'
    });

    return {
      configId,
      generatedAt,
      targetDomain: config.targetDomain,
      obfuscatedScript: scriptCode,
      scriptIntegrityHash
    };
  }

  public recordTamperEvent(event: Omit<ClientTamperEvent, 'eventId' | 'timestamp'>): ClientTamperEvent {
    const newEvent: ClientTamperEvent = {
      eventId: `tmp-${crypto.randomUUID()}`,
      timestamp: new Date().toISOString(),
      ...event
    };

    this.events.unshift(newEvent);

    auditLogService.log({
      actor: 'CLIENT_BEACON',
      action: 'CLIENT_TAMPER_EVENT_RECORDED',
      details: JSON.stringify({
        eventId: newEvent.eventId,
        tamperType: newEvent.tamperType,
        domain: newEvent.targetDomain,
        severity: newEvent.severity
      }),
      category: 'SECURITY',
      severity: newEvent.severity === 'CRITICAL' ? 'CRITICAL' : 'WARNING'
    });

    return newEvent;
  }

  public listTamperEvents(): ClientTamperEvent[] {
    return this.events;
  }
}

export const clientTamperDefenseService = new ClientTamperDefenseService();
